name := $(shell dasel -f Cargo.toml package.name)

.PHONY: dev debug release test clean

dev:
	while true; do fd . | entr -ccd make lint test release; done

debug:
	mkdir -p dist

	cargo build
	ln -f "target/debug/${name}" "dist/"
	ln -f "target/debug/listener" "dist/"

release:
	mkdir -p dist

	cargo build --release
	ln -f "target/release/${name}" "dist/"
	ln -f "target/release/listener" "dist/"

test:
	cargo test -- --nocapture --test-threads=1

lint:
	cargo clippy

lint-fix:
	fd -e rs -x rustfmt
	cargo clippy --fix --allow-dirty

clean:
	cargo clean
