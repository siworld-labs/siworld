use super::*;
fn directory() -> PathBuf {
    let mut token = [0; 16];
    getrandom::fill(&mut token).unwrap();
    std::env::temp_dir().join(format!(
        "siworld-native-local-{}",
        token.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}
#[test]
fn new_directory_is_explicit_and_existing_data_is_never_overwritten() {
    let path = directory();
    let config = initialize(&path, 0).unwrap();
    assert_eq!(load(&path).unwrap(), config);
    assert!(initialize(&path, 0).is_err());
    assert_eq!(load(&path).unwrap(), config);
    std::fs::remove_dir_all(path).unwrap();
}
#[test]
fn malformed_configuration_is_rejected() {
    let path = directory();
    initialize(&path, 0).unwrap();
    std::fs::write(path.join(CONFIG_FILE), [0; 41]).unwrap();
    assert!(load(&path).is_err());
    std::fs::remove_dir_all(path).unwrap();
}
#[test]
fn reward_material_is_write_once_and_survives_reload() {
    let path = directory();
    initialize(&path, 0).unwrap();
    save_reward(&path, &[3; 32], b"private test material").unwrap();
    assert!(save_reward(&path, &[3; 32], b"replacement").is_err());
    assert_eq!(
        read_reward(&path, &[3; 32]).unwrap().as_slice(),
        b"private test material"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(reward_path(&path, &[3; 32]))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    std::fs::remove_dir_all(path).unwrap();
}
#[cfg(unix)]
#[test]
fn symlink_configuration_and_directory_are_rejected() {
    use std::os::unix::fs::symlink;
    let path = directory();
    initialize(&path, 0).unwrap();
    let alias = directory();
    symlink(&path, &alias).unwrap();
    assert!(load(&alias).is_err());
    std::fs::remove_file(alias).unwrap();
    let config = path.join(CONFIG_FILE);
    let moved = path.join("moved");
    std::fs::rename(&config, &moved).unwrap();
    symlink(&moved, &config).unwrap();
    assert!(load(&path).is_err());
    std::fs::remove_dir_all(path).unwrap();
}

#[cfg(unix)]
#[test]
fn nonprivate_directory_and_receipt_permissions_are_rejected() {
    use std::os::unix::fs::PermissionsExt;
    let path = directory();
    initialize(&path, 0).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(load(&path).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    save_reward(&path, &[7; 32], b"private test").unwrap();
    std::fs::set_permissions(
        reward_path(&path, &[7; 32]),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(read_reward(&path, &[7; 32]).is_err());
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn asert_configuration_roundtrips_and_refuses_legacy_without_rewrite() {
    let path = directory();
    let config = initialize_asert(&path, 1_700_000_000, [0x7f; 32], 100).unwrap();
    assert_eq!(load(&path).unwrap(), config);
    let original = std::fs::read(path.join(CONFIG_FILE)).unwrap();
    assert!(initialize_asert(&path, 1_700_000_001, [0x7f; 32], 100).is_err());
    assert_eq!(std::fs::read(path.join(CONFIG_FILE)).unwrap(), original);
    let mut legacy = b"SWNDv1\0\0".to_vec();
    legacy.extend_from_slice(&[9; 32]);
    legacy.push(0);
    std::fs::write(path.join(CONFIG_FILE), &legacy).unwrap();
    assert!(load(&path).is_err());
    assert_eq!(std::fs::read(path.join(CONFIG_FILE)).unwrap(), legacy);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn pre_issuance_local_rules_are_rejected_without_modifying_existing_bytes() {
    let path = directory();
    let config = initialize(&path, 0).unwrap();
    let mut legacy = b"SWNDv2\0\0".to_vec();
    legacy.extend_from_slice(&config.encode_rules()[..227]);
    std::fs::write(path.join(CONFIG_FILE), &legacy).unwrap();
    assert!(load(&path).is_err());
    assert_eq!(std::fs::read(path.join(CONFIG_FILE)).unwrap(), legacy);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn two_fingerprint_fund_configuration_is_rejected_and_preserved() {
    let path = directory();
    initialize(&path, 0).unwrap();
    let mut legacy = b"SWNDv3\0\0".to_vec();
    legacy.extend_from_slice(&[0; 279]);
    std::fs::write(path.join(CONFIG_FILE), &legacy).unwrap();
    assert!(load(&path).unwrap_err().contains("no automatic migration"));
    assert_eq!(std::fs::read(path.join(CONFIG_FILE)).unwrap(), legacy);
    std::fs::remove_dir_all(path).unwrap();
}
