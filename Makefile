SHELL=/bin/bash

TARGET_ARCHS ?= x86_64-unknown-linux-gnu

release:
	@git diff --quiet || { echo "Run in a clean repo"; exit 1; }
	cargo bump $(shell cfsetup release next-tag)
	cargo update
	git add Cargo.toml Cargo.lock
	git commit -m "Bump version in Cargo.toml to release tag"
	cfsetup release update

cf-package:
	for TARGET_ARCH in $(TARGET_ARCHS); do \
		echo $$TARGET_ARCH && \
		cargo deb --target $$TARGET_ARCH && \
		mv target/$$TARGET_ARCH/debian/*.deb ./ || \
		exit 1; \
	done

