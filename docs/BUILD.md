# Building & verifying Runbound

## Reproducible build

Release binaries are built in CI from a pinned toolchain. To reproduce locally:

```bash
# 1. Use the toolchain pinned by the repo (rust-toolchain.toml if present, else stable)
rustup show

# 2. Build the same targets as the release workflow (.github/workflows/release.yml)
cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-musl

# 3. Compare against the published checksums
sha256sum target/x86_64-unknown-linux-gnu/release/runbound
# must match the line in the release SHA256SUMS
```

Determinism notes: build from a clean checkout of the tagged commit, with the same
Rust version and the locked dependency set (`Cargo.lock`). Differences usually come
from a different toolchain version or build path; pin both to reproduce byte-for-byte.

## Integrity & signatures

Every release publishes:

- the four static binaries (`runbound-{x86_64,aarch64}-linux-{gnu,musl}`),
- **`SHA256SUMS`** — checksums of all binaries + the SBOM,
- **`sbom.cdx.json`** — CycloneDX SBOM (all crates + versions),
- **`*.minisig`** — [minisign](https://jedisct1.github.io/minisign/) signatures. Every release since **v0.15.0** is signed; verify with the public key below.

### Verify checksums

```bash
sha256sum -c SHA256SUMS
```

### Verify signatures (minisign)

```bash
# RUNBOUND_PUBKEY is published below / in the release notes
minisign -Vm runbound-x86_64-linux-gnu -P "RWT4uccC0fq9zgcaMtMsdH90azvmKpsNI1xlZrzlBuGH7xx1nDftTFJr"
minisign -Vm SHA256SUMS               -P "RWT4uccC0fq9zgcaMtMsdH90azvmKpsNI1xlZrzlBuGH7xx1nDftTFJr"
```

The signing public key:

```
untrusted comment: Runbound release signing key (minisign)
RWT4uccC0fq9zgcaMtMsdH90azvmKpsNI1xlZrzlBuGH7xx1nDftTFJr
```

## Enabling signing (maintainer, one-time)

```bash
minisign -G -W                   # generates (no passphrase: required for unattended CI signing) minisign.key (private) + minisign.pub (public)
# 1. Add the *private* key file contents as repo secret MINISIGN_SECRET (Settings → Secrets → Actions)
# 1b. If the key has a passphrase (recommended), also add it as repo secret MINISIGN_PASSWORD
# 2. Paste the *public* key (minisign.pub) into the block above and commit
```

Once `MINISIGN_SECRET` is set, the release workflow signs every artifact automatically.
Until then, releases ship with `SHA256SUMS` only (no `.minisig`).
