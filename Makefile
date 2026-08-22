BINARY = bua
VERSION = $(shell sed -nE 's/^version[[:space:]]*=[[:space:]]*"([0-9]+\.[0-9]+\.[0-9]+)".*/\1/p' Cargo.toml | head -n 1)

# Forwarded into the cross-build container, which does not inherit the host environment.
BUILD_ENV = SERVICES_KEY_AICHAT BRAVE_SERVICES_KEY_ID BRAVE_AI_CHAT_ENDPOINT \
            BRAVE_AI_CHAT_PREMIUM_ENDPOINT MODEL BUA_ALLOW_UNCONFIGURED_BUILD

.PHONY: help
help:
	@echo "bua $(VERSION)"
	@echo
	@echo "Development:"
	@echo "  make build          Debug build"
	@echo "  make test           Run all tests"
	@echo "  make check          Format check, clippy, and tests"
	@echo "  make check-linux    The same checks on Linux, current stable toolchain"
	@echo "  make fmt            Apply formatting"
	@echo
	@echo "Reproducible cross-builds (requires Docker):"
	@echo "  make all-platforms  Every target below"
	@echo "  make darwin-arm64   macOS Apple silicon"
	@echo "  make darwin-amd64   macOS Intel"
	@echo "  make linux-amd64    Linux x86_64"
	@echo "  make linux-arm64    Linux aarch64"
	@echo "  make windows-amd64  Windows x86_64"
	@echo "  make windows-arm64  Windows aarch64"
	@echo
	@echo "  make clean          Remove build output"

.PHONY: build
build:
	cargo build

.PHONY: test
test:
	cargo test --all

.PHONY: fmt
fmt:
	cargo fmt --all

# Everything CI enforces, runnable locally before pushing.
.PHONY: check
check:
	cargo fmt --all -- --check
	cargo clippy --all-targets --all-features -- -D warnings
	cargo test --all

# Runs the same checks on Linux with the current stable toolchain. Worth doing before
# pushing platform-specific code: a macOS host never compiles the Linux backend, and
# clippy gains lints between releases, so both can fail in CI while passing locally.
.PHONY: check-linux
check-linux:
	docker run --rm --platform linux/amd64 -v "$(PWD):/src:ro" -w /work rust:slim sh -c '\
		cp -r /src/. /work && \
		rustup component add clippy rustfmt >/dev/null 2>&1 && \
		cargo fmt --all -- --check && \
		cargo clippy --all-targets --all-features -- -D warnings && \
		cargo test --all'

.PHONY: darwin-arm64
darwin-arm64:
	$(call cross-build,$@,aarch64-apple-darwin)

.PHONY: darwin-amd64
darwin-amd64:
	$(call cross-build,$@,x86_64-apple-darwin)

.PHONY: linux-amd64
linux-amd64:
	$(call cross-build,$@,x86_64-unknown-linux-gnu)

.PHONY: linux-arm64
linux-arm64:
	$(call cross-build,$@,aarch64-unknown-linux-gnu)

.PHONY: windows-amd64
windows-amd64:
	$(call cross-build,$@,x86_64-pc-windows-gnu)

.PHONY: windows-arm64
windows-arm64:
	$(call cross-build,$@,aarch64-pc-windows-gnullvm)

.PHONY: all-platforms
all-platforms: darwin-arm64 darwin-amd64 linux-amd64 linux-arm64 windows-amd64 windows-arm64
	@echo
	@echo "built:"
	@ls -1 dist/

# Symbols are kept during the build because Rust's own strip can corrupt some targets
# under zigbuild, so they are removed here instead.
#
# rust-objcopy is LLVM-based and handles Mach-O, ELF, and PE alike, so one tool covers
# every target; the per-target GNU strip binaries are not all present in the image.
RUST_LIB_DIR = /usr/local/rustup/toolchains/1.93.0-x86_64-unknown-linux-gnu/lib
STRIP_TOOL = $(RUST_LIB_DIR)/rustlib/x86_64-unknown-linux-gnu/bin/rust-objcopy
.PHONY: strip
strip:
	@for f in dist/$(BINARY)-*; do \
		case "$$f" in *.sha256|*SHA256SUMS) continue;; esac; \
		docker run --rm -v "$(PWD)/dist:/dist" \
			-e LD_LIBRARY_PATH=$(RUST_LIB_DIR) \
			ghcr.io/rust-cross/cargo-zigbuild:0.23.0 \
			$(STRIP_TOOL) --strip-all "/dist/$$(basename $$f)"; \
	done
	@echo "stripped:"
	@ls -lh dist/ | awk 'NR>1 {print "  " $$9, $$5}'

.PHONY: checksums
checksums:
	@cd dist && rm -f ./*.sha256 SHA256SUMS && \
	for f in $(BINARY)-*; do \
		shasum -a 256 "$$f" | awk '{print $$1}' > "$$f.sha256"; \
		shasum -a 256 "$$f" >> SHA256SUMS; \
	done
	@echo "wrote dist/SHA256SUMS"

.PHONY: clean
clean:
	cargo clean
	rm -rf dist

# Configuration reaches the build as a BuildKit secret rather than a build argument,
# which would record the signing key in the image metadata. The temporary file is
# mode 600 and removed even if the build fails.
define cross-build
	set -e; \
	env_file="$$(mktemp)"; trap 'rm -f "$$env_file"' EXIT INT TERM; \
	for name in $(BUILD_ENV); do \
		eval "value=\$$$$name"; \
		if [ -n "$$value" ]; then printf 'export %s=%s\n' "$$name" "$$value" >> "$$env_file"; fi; \
	done; \
	DOCKER_BUILDKIT=1 docker build -f Dockerfile.cross -t $(BINARY)-$(1) \
		--build-arg TARGET=$(2) \
		--secret id=bua_env,src="$$env_file" .
	$(call extract,$(BINARY)-$(1),$(1))
endef

# `docker create` on a scratch image needs a command argument even though it never
# runs; the container exists only so the binary can be copied out.
define extract
	mkdir -p dist
	docker rm -f tmp-$(BINARY)-$(2) 2>/dev/null || true
	docker create --name tmp-$(BINARY)-$(2) $(1) /dev/null
	docker cp tmp-$(BINARY)-$(2):/$(BINARY) dist/$(call artifact,$(2))
	docker rm tmp-$(BINARY)-$(2)
endef

define artifact
$(BINARY)-$(1)$(if $(findstring windows,$(1)),.exe,)
endef
