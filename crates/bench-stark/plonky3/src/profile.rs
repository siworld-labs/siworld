//! Fixed-label events for the isolated benchmark. Never emits proof inputs.
use std::sync::OnceLock;
use std::time::Instant;

pub struct Span(&'static str);

impl Span {
    pub fn new(name: &'static str) -> Self {
        emit(name, "start");
        Self(name)
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        emit(self.0, "end");
    }
}

fn emit(name: &str, event: &str) {
    if std::env::var_os("SIWORLD_BENCH_PROFILE").is_none() {
        return;
    }
    static START: OnceLock<Instant> = OnceLock::new();
    let elapsed = START.get_or_init(Instant::now).elapsed().as_nanos();
    eprintln!(
        "{{\"phase\":\"{name}\",\"event\":\"{event}\",\"ns\":{elapsed},\"thread\":\"{:?}\"}}",
        std::thread::current().id()
    );
}
