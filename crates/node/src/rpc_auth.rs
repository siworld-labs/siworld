//! Independent bearer capabilities for a loopback-only RPC transport.

use crate::secrets::{read_secret, write_secret};
use serde_json::Value;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

pub const READ_TOKEN_FILE: &str = "rpc-read.token";
pub const SPEND_TOKEN_FILE: &str = "rpc-spend.token";
pub const FUND_TOKEN_FILE: &str = "rpc-devfund.token";

/// A 256-bit credential. Debug never reveals it; owned bytes erase on drop.
pub struct RpcToken(Zeroizing<[u8; 32]>);

impl core::fmt::Debug for RpcToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RpcToken(REDACTED)")
    }
}

impl RpcToken {
    pub fn from_hex(text: &str) -> Option<Self> {
        crate::parse_hex(text).map(|bytes| Self(Zeroizing::new(bytes)))
    }

    pub fn read(path: &Path) -> Result<Self, String> {
        let text = read_secret(path)?;
        Self::from_hex(text.trim()).ok_or_else(|| "invalid RPC credential file".into())
    }

    pub fn generate_file(path: &Path) -> Result<(), String> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| "OS randomness unavailable")?;
        Self(bytes).write(path)
    }

    fn write(&self, path: &Path) -> Result<(), String> {
        let text = self.to_hex();
        write_secret(path, &text)
    }

    pub(crate) fn to_hex(&self) -> Zeroizing<String> {
        use std::fmt::Write;
        let mut text = Zeroizing::new(String::with_capacity(64));
        for byte in self.0.iter() {
            write!(text, "{byte:02x}").expect("writing a string");
        }
        text
    }

    fn fingerprint(&self) -> blake3::Hash {
        blake3::hash(self.0.as_ref())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Permission {
    Read,
    Spend,
    DevFund,
}

impl Permission {
    pub(crate) fn allows(self, method: &str) -> bool {
        match method {
            "info" => true,
            "address" | "balance" | "walletstatus" | "paymentstatus" => {
                matches!(self, Self::Read | Self::Spend)
            }
            "send" | "walletlock" | "walletunlock" => self == Self::Spend,
            "devfund" | "fundpayoutstatus" | "fundstatus" | "fundlock" | "fundunlock"
            | "fundapprovals" | "fundbudgethistory" => self == Self::DevFund,
            _ => false,
        }
    }
}

/// The server retains only fingerprints, compared using BLAKE3's constant-time
/// Hash equality. Duplicate credentials are rejected instead of merging rights.
pub struct RpcAuth {
    tokens: Vec<(blake3::Hash, Permission)>,
}

impl RpcAuth {
    pub fn new(
        read: RpcToken,
        spend: Option<RpcToken>,
        fund: Option<RpcToken>,
    ) -> Result<Self, String> {
        let mut tokens = vec![(read.fingerprint(), Permission::Read)];
        for (token, permission) in [(spend, Permission::Spend), (fund, Permission::DevFund)] {
            if let Some(token) = token {
                let hash = token.fingerprint();
                if tokens.iter().any(|(h, _)| *h == hash) {
                    return Err("RPC capabilities must use distinct credentials".into());
                }
                tokens.push((hash, permission));
            }
        }
        Ok(Self { tokens })
    }

    /// Removes and erases the supplied credential before the request is queued.
    pub(crate) fn authenticate(&self, request: &mut Value) -> Option<Permission> {
        let mut auth = request.as_object_mut()?.remove("auth")?;
        if !auth.is_string() {
            erase_json(&mut auth);
            return None;
        }
        let Value::String(mut text) = auth else {
            unreachable!()
        };
        let token = RpcToken::from_hex(&text);
        text.zeroize();
        let hash = token?.fingerprint();
        let mut matched = None;
        for (expected, permission) in &self.tokens {
            if *expected == hash {
                matched = Some(*permission);
            }
        }
        matched
    }
}

/// Erase parsed request strings, including malformed credential shapes.
pub fn erase_json(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(erase_json),
        Value::Object(fields) => fields.values_mut().for_each(erase_json),
        _ => {}
    }
    *value = Value::Null;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn token(byte: u8) -> RpcToken {
        RpcToken::from_hex(&format!("{byte:02x}").repeat(32)).unwrap()
    }

    #[test]
    fn capabilities_are_separate_and_unknown_methods_fail_closed() {
        let auth = RpcAuth::new(token(1), Some(token(2)), Some(token(3))).unwrap();
        for (byte, scope) in [
            (1, Permission::Read),
            (2, Permission::Spend),
            (3, Permission::DevFund),
        ] {
            let mut request = json!({"auth": &*token(byte).to_hex(), "authorized": true});
            assert_eq!(auth.authenticate(&mut request), Some(scope));
            assert!(request.get("auth").is_none());
            assert!(!scope.allows("future-wallet-method"));
        }
        assert!(!Permission::Read.allows("send"));
        assert!(!Permission::Read.allows("devfund"));
        assert!(!Permission::Spend.allows("devfund"));
        assert!(!Permission::DevFund.allows("send"));
        assert!(!Permission::DevFund.allows("balance"));
        assert!(RpcAuth::new(token(1), Some(token(1)), None).is_err());
        assert!(RpcAuth::new(token(1), None, None)
            .unwrap()
            .authenticate(&mut json!({"auth": &*token(2).to_hex()}))
            .is_none());
        assert_eq!(format!("{:?}", token(1)), "RpcToken(REDACTED)");
    }
}
