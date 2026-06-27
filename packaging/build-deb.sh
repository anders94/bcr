#!/usr/bin/env bash
# Build Debian packages for bcr by cross-compiling inside a Debian Rust
# container. A single native-arch container builds every requested architecture
# (amd64 is cross-compiled with gcc-x86-64-linux-gnu rather than emulated), so
# crates download once and both builds run at native speed.
#
# Produces target/<triple>/debian/bcr_<version>_<arch>.deb for each arch.
#
# Usage:
#   packaging/build-deb.sh              # both amd64 and arm64
#   packaging/build-deb.sh amd64        # just amd64
#   packaging/build-deb.sh arm64 amd64  # explicit list
#
# Requires Docker. The container platform defaults to the host arch; override
# with BUILD_PLATFORM=linux/amd64 if you are on an x86_64 host.
set -euo pipefail

cd "$(dirname "$0")/.."

archs=("$@")
[ ${#archs[@]} -eq 0 ] && archs=(amd64 arm64)

docker run --rm \
  ${BUILD_PLATFORM:+--platform "$BUILD_PLATFORM"} \
  -e ARCHS="${archs[*]}" \
  -v "$PWD":/build -w /build \
  rust:bookworm bash -euo pipefail -c '
    set -x
    apt-get update -qq
    apt-get install -y -qq gcc-x86-64-linux-gnu >/dev/null
    rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu >/dev/null
    cargo install cargo-deb --locked
    # A native package wants its changelog named changelog.gz (see Cargo.toml);
    # -n keeps the gzip reproducible (no stored name/timestamp).
    gzip -9nc packaging/changelog > packaging/changelog.gz
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc
    for a in $ARCHS; do
      case "$a" in
        amd64) t=x86_64-unknown-linux-gnu ;;
        arm64) t=aarch64-unknown-linux-gnu ;;
        *) echo "unknown arch: $a" >&2; exit 2 ;;
      esac
      echo "=== building $a ($t) ==="
      # --no-strip: the release profile already strips via rustc; a host-arch
      # strip cannot process a cross-built ELF anyway.
      cargo deb --target "$t" --no-strip
    done
    echo "=== artifacts ==="
    ls -l target/*/debian/*.deb
  '
