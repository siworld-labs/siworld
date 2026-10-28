//! Peer-to-peer messages and their byte encoding.
//!
//! Nodes talk over one libp2p request-response protocol per network,
//! `/siworld/<genesis id>/1`, so nodes of different testnets never exchange
//! messages. A node announces a block or a transaction by sending it to each
//! peer; a peer that accepts it as new sends it on, and one that already has
//! it stops, so announcements flood the network once. A node behind asks a
//! peer for the main-chain blocks after its locator.
//!
//! Every message is `u8 kind ‖ payload`, read to the end of the stream with a
//! length limit for its kind: a transaction request is at most one encoded
//! transaction, a locator at most [`MAX_LOCATOR`] hashes, and the response to
//! an announcement one byte. Blocks and transactions inside are opaque bytes
//! here and are decoded by the receiver.

use std::io;

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::StreamProtocol;
use siworld_core::codec::{decode_all, DecodeError, Reader, MAX_PROOF_LEN};
use siworld_core::Digest;

use crate::wire::TX_MAX_LEN;

/// Largest request: one block with the longest proof, and some headroom.
pub const MAX_REQUEST: usize = MAX_PROOF_LEN + (1 << 20);
/// Largest response.
pub const MAX_RESPONSE: usize = 64 << 20;
/// Most blocks in one response; fewer when they would exceed
/// [`MAX_RESPONSE`].
pub const MAX_BATCH: usize = 32;
/// Most hashes in a locator: about 10 dense entries and 64 doublings.
pub const MAX_LOCATOR: usize = 128;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Request {
    /// A block the sender accepted.
    Block(Vec<u8>),
    /// A transaction the sender admitted to its mempool.
    Tx(Vec<u8>),
    /// The main-chain blocks after the first locator entry the peer knows.
    GetBlocks(Vec<Digest>),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Response {
    Ack,
    Blocks(Vec<Vec<u8>>),
}

pub fn protocol(genesis: &Digest) -> StreamProtocol {
    StreamProtocol::try_from_owned(format!("/siworld/{}/1", crate::hex(genesis)))
        .expect("starts with a slash")
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Block(b) => {
                out.push(0);
                out.extend_from_slice(b);
            }
            Self::Tx(t) => {
                out.push(1);
                out.extend_from_slice(t);
            }
            Self::GetBlocks(locator) => {
                out.push(2);
                out.extend_from_slice(&(locator.len() as u32).to_le_bytes());
                for d in locator {
                    out.extend_from_slice(d.as_bytes());
                }
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (&kind, rest) = bytes.split_first().ok_or(DecodeError::Truncated)?;
        match kind {
            0 => Ok(Self::Block(rest.to_vec())),
            1 => Ok(Self::Tx(rest.to_vec())),
            2 => decode_all(rest, |r: &mut Reader| {
                let n = r.length(MAX_LOCATOR)?;
                let locator = (0..n).map(|_| r.digest()).collect::<Result<_, _>>()?;
                Ok(Self::GetBlocks(locator))
            }),
            _ => Err(DecodeError::TooLong),
        }
    }
}

impl Response {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Ack => vec![0],
            Self::Blocks(blocks) => {
                let mut out = vec![1];
                out.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
                for b in blocks {
                    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                    out.extend_from_slice(b);
                }
                out
            }
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (&kind, rest) = bytes.split_first().ok_or(DecodeError::Truncated)?;
        match kind {
            0 if rest.is_empty() => Ok(Self::Ack),
            0 => Err(DecodeError::TrailingBytes),
            1 => decode_all(rest, |r: &mut Reader| {
                let n = r.length(MAX_BATCH)?;
                let blocks = (0..n)
                    .map(|_| {
                        let len = r.length(MAX_RESPONSE)?;
                        Ok(r.take(len)?.to_vec())
                    })
                    .collect::<Result<_, _>>()?;
                Ok(Self::Blocks(blocks))
            }),
            _ => Err(DecodeError::TooLong),
        }
    }
}

/// Longest payload of a request of kind `kind`.
fn request_limit(kind: u8) -> Option<usize> {
    match kind {
        0 => Some(MAX_REQUEST - 1),
        1 => Some(TX_MAX_LEN),
        2 => Some(4 + MAX_LOCATOR * 32),
        _ => None,
    }
}

/// Longest response to `request`.
fn response_limit(request: &Request) -> usize {
    match request {
        Request::Block(_) | Request::Tx(_) => 1,
        Request::GetBlocks(_) => MAX_RESPONSE,
    }
}

/// The request-response codec: each message is the whole stream.
///
/// libp2p writes a request and reads its response with the same copy of the
/// codec, which remembers in between how long the response may be.
#[derive(Clone, Copy)]
pub struct Codec {
    response_limit: usize,
}

impl Default for Codec {
    fn default() -> Self {
        Self {
            response_limit: MAX_RESPONSE,
        }
    }
}

async fn read_limited<T: AsyncRead + Unpin + Send>(io: &mut T, max: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    io.take(max as u64 + 1).read_to_end(&mut bytes).await?;
    if bytes.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too long",
        ));
    }
    Ok(bytes)
}

fn invalid(e: DecodeError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}"))
}

impl libp2p::request_response::Codec for Codec {
    type Protocol = StreamProtocol;
    type Request = Request;
    type Response = Response;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut kind = [0];
        io.read_exact(&mut kind).await?;
        let limit = request_limit(kind[0]).ok_or_else(|| invalid(DecodeError::TooLong))?;
        let mut bytes = kind.to_vec();
        bytes.extend(read_limited(io, limit).await?);
        Request::decode(&bytes).map_err(invalid)
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        Response::decode(&read_limited(io, self.response_limit).await?).map_err(invalid)
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        req: Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        self.response_limit = response_limit(&req);
        io.write_all(&req.encode()).await?;
        io.close().await
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        res: Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&res.encode()).await?;
        io.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip() {
        let requests = [
            Request::Block(vec![1, 2, 3]),
            Request::Tx(vec![]),
            Request::GetBlocks(vec![Digest([1; 32]), Digest([2; 32])]),
        ];
        for r in requests {
            assert_eq!(Request::decode(&r.encode()), Ok(r));
        }
        for r in [Response::Ack, Response::Blocks(vec![vec![], vec![9; 5]])] {
            assert_eq!(Response::decode(&r.encode()), Ok(r));
        }
    }

    #[test]
    fn malformed_messages_are_rejected() {
        assert!(Request::decode(&[]).is_err());
        assert!(Request::decode(&[7]).is_err());
        let mut long = Request::GetBlocks(vec![Digest::ZERO; MAX_LOCATOR + 1]).encode();
        assert_eq!(Request::decode(&long), Err(DecodeError::TooLong));
        long.truncate(5);
        assert!(Request::decode(&long).is_err());
        assert_eq!(Response::decode(&[0, 0]), Err(DecodeError::TrailingBytes));
        let mut blocks = Response::Blocks(vec![vec![1]]).encode();
        blocks.push(0);
        assert_eq!(Response::decode(&blocks), Err(DecodeError::TrailingBytes));
    }

    fn read_request(bytes: &[u8]) -> io::Result<Request> {
        use libp2p::request_response::Codec as _;
        let protocol = protocol(&Digest::ZERO);
        futures::executor::block_on(Codec::default().read_request(&protocol, &mut &bytes[..]))
    }

    /// Writes `request` and reads `response` with one codec, as libp2p does.
    fn exchange(request: Request, response: &Response) -> io::Result<Response> {
        use libp2p::request_response::Codec as _;
        let protocol = protocol(&Digest::ZERO);
        let mut codec = Codec::default();
        let mut sink = futures::io::Cursor::new(Vec::new());
        futures::executor::block_on(async {
            codec.write_request(&protocol, &mut sink, request).await?;
            codec
                .read_response(&protocol, &mut &response.encode()[..])
                .await
        })
    }

    #[test]
    fn requests_are_limited_by_kind() {
        let tx = Request::Tx(vec![0; TX_MAX_LEN]);
        assert_eq!(read_request(&tx.encode()).unwrap(), tx);
        let long_tx = Request::Tx(vec![0; TX_MAX_LEN + 1]).encode();
        assert!(read_request(&long_tx).is_err());
        let locator = Request::GetBlocks(vec![Digest::ZERO; MAX_LOCATOR]);
        assert_eq!(read_request(&locator.encode()).unwrap(), locator);
        let mut long_locator = locator.encode();
        long_locator.push(0);
        assert!(read_request(&long_locator).is_err());
        assert!(read_request(&[9, 0]).is_err());
        let block = Request::Block(vec![0; MAX_REQUEST - 1]);
        assert!(read_request(&block.encode()).is_ok());
        assert!(read_request(&Request::Block(vec![0; MAX_REQUEST]).encode()).is_err());
    }

    #[test]
    fn an_announcement_is_answered_by_one_byte() {
        let blocks = Response::Blocks(vec![vec![0; 64]]);
        let announce = Request::Tx(vec![]);
        assert_eq!(
            exchange(announce.clone(), &Response::Ack).unwrap(),
            Response::Ack
        );
        assert!(exchange(announce, &blocks).is_err());
        let get = Request::GetBlocks(vec![Digest::ZERO]);
        assert_eq!(exchange(get, &blocks).unwrap(), blocks);
    }
}
