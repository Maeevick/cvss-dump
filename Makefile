ci-gate:
	cargo fmt --check && cargo clippy && cargo check && cargo test
