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
