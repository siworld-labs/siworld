//! Explicit miner template preferences, separate from immutable chain rules.
use crate::producer::MiningSettings;
use crate::state::RewardMode;
use crate::wire::Hash;
use native::codec::{decode_digest, encode_digest};
use native::encryption::PaymentAddress;
use std::path::Path;
const FILE: &str = "mining-preferences.json";

fn unhex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != 2 * N
        || value
            .bytes()
            .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
    {
        return Err("noncanonical mining preference hex".into());
    }
    let mut out = [0; N];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let digit = |b| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        out[index] = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    Ok(out)
}
pub fn save(directory: &Path, network: Hash, settings: &MiningSettings) -> Result<(), String> {
    let value = serde_json::json!({
        "version":1,"network":crate::local::hex(&network),
        "reward_mode":settings.mode.name(),
        "owner":crate::local::hex(&encode_digest(&settings.recipient.owner())),
        "encapsulation_key":crate::local::hex(settings.recipient.encapsulation_key()),
    });
    crate::service::atomic_json(&directory.join(FILE), &value)
}
pub fn load(directory: &Path, network: Hash) -> Result<MiningSettings, String> {
    use std::io::Read;
    let file = crate::local::regular_read(&directory.join(FILE), true, 8192)
        .map_err(|_| "explicit reward_mode and backed-up wallet address are required".to_owned())?;
    let mut bytes = Vec::new();
    file.take(8193)
        .read_to_end(&mut bytes)
        .map_err(|_| "mining preferences read failed")?;
    if bytes.len() > 8192 {
        return Err("mining preferences byte limit".into());
    }
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| "invalid mining preferences")?;
    let object = value
        .as_object()
        .ok_or("mining preferences must be an object")?;
    if object.len() != 5 || value["version"] != 1 || value["network"] != crate::local::hex(&network)
    {
        return Err("mining preferences version or network mismatch".into());
    }
    let text = |key| value[key].as_str().ok_or("missing mining preference field");
    let mode = RewardMode::from_name(text("reward_mode")?).map_err(|e| e.to_string())?;
    let owner = decode_digest(&unhex::<48>(text("owner")?)?).map_err(|_| "invalid miner owner")?;
    let recipient = PaymentAddress::new(owner, unhex::<1184>(text("encapsulation_key")?)?)
        .map_err(|_| "invalid mining payment address")?;
    Ok(MiningSettings { mode, recipient })
}
/// Import a canonical public payment address from a bounded private local file.
/// A wallet must back up its seed before providing this file to the miner.
pub fn read_address(path: &Path) -> Result<PaymentAddress, String> {
    use std::io::Read;
    let file = crate::local::regular_read(path, true, 1232)?;
    let mut bytes = Vec::new();
    file.take(1233)
        .read_to_end(&mut bytes)
        .map_err(|_| "address read failed")?;
    if bytes.len() != 1232 {
        return Err("payment address must be exactly 1232 bytes".into());
    }
    let owner = decode_digest(bytes[..48].try_into().expect("fixed owner"))
        .map_err(|_| "invalid address owner")?;
    PaymentAddress::new(owner, bytes[48..].try_into().expect("fixed KEM key"))
        .map_err(|_| "invalid payment address".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;
    #[test]
    fn no_default_mode_and_updates_preserve_existing_templates() {
        let mut entropy = [0; 16];
        getrandom::fill(&mut entropy).unwrap();
        let directory =
            std::env::temp_dir().join(format!("siworld-mining-{}", crate::local::hex(&entropy)));
        crate::local::initialize(&directory, 0).unwrap();
        let network = crate::local::load(&directory).unwrap().network;
        assert!(load(&directory, network).is_err());
        let keys =
            crate::wallet::WalletKeys::from_seed(network, Zeroizing::new([42; 32]), 0).unwrap();
        save(
            &directory,
            network,
            &MiningSettings {
                mode: RewardMode::Voyager,
                recipient: keys.address(),
            },
        )
        .unwrap();
        let template = load(&directory, network).unwrap();
        save(
            &directory,
            network,
            &MiningSettings {
                mode: RewardMode::Holder,
                recipient: keys.address(),
            },
        )
        .unwrap();
        assert_eq!(template.mode, RewardMode::Voyager);
        assert_eq!(load(&directory, network).unwrap().mode, RewardMode::Holder);
        assert!(load(&directory, [1; 32]).is_err());
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(directory.join(FILE)).unwrap()).unwrap();
        value["reward_mode"] = "automatic".into();
        crate::service::atomic_json(&directory.join(FILE), &value).unwrap();
        assert!(load(&directory, network).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
