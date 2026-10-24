## Summary

<!-- What does this change do, and why? -->

## Checklist

- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, and `cargo test --workspace` pass.
- [ ] Consensus changes have tests written before the implementation.
- [ ] No floating point on consensus paths; amounts are in atoms.
- [ ] No new per-block public statistics and no user-linkable fields in logs or metrics.
- [ ] Documentation is updated, and `docs/protocol.md` is respected.
