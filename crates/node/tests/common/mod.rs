//! Owner-only test journal directories, removed after the service has stopped.
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
#[allow(dead_code)]
pub struct JournalDir(pub PathBuf);
#[allow(dead_code)]
impl JournalDir {
    pub fn attach(node: &mut siworld_node::node::Node) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "siworld-rpc-journal-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        node.enable_payment_journal(&path.join("payments.redb"))
            .unwrap();
        Self(path)
    }
}
impl Drop for JournalDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[allow(dead_code)]
pub struct FundDir(pub PathBuf);
#[allow(dead_code)]
impl FundDir {
    pub fn attach(
        node: &mut siworld_node::node::Node,
        store: siworld_node::fund_keys::FundKeystore,
        password: &str,
    ) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "siworld-fund-journal-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        siworld_node::fund_payments::initialize(&path, &store, password, &node.genesis).unwrap();
        node.protect_dev_fund(store, password, &path).unwrap();
        Self(path)
    }
}
impl Drop for FundDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
