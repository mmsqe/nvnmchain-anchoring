.PHONY: check lint test

check: lint test

lint:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings

test:
	cargo test
