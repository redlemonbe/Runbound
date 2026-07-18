
# Installing Runbound

This guide covers the `install.sh` script — what it does, how to verify what it installs,
and how to remove it. For configuration after install, see
[configuration.md](configuration.md); for the XDP fast path, see [xdp.md](xdp.md); for
build-from-source and signature details, see [BUILD.md](BUILD.md).

## Requirements

- Linux, `x86_64` or `aarch64`.
- `systemd`.
- Root (the script installs a system service).
- **Port 53 free** — stop any existing resolver first (`unbound`, `bind9`/`named`,
  `systemd-resolved`, `dnsmasq`). The installer detects these and aborts with the exact
  command to run if one is active.
- `curl` or `wget`. `sha256sum` (coreutils) is used for integrity; `minisign` is used for
  signature verification if present. The binary itself is a static musl build with no
  runtime dependencies.

## Quick install

```bash
curl -fsSL https://raw.githubusercontent.com/redlemonbe/Runbound/main/install.sh | sudo bash
```

The installer prints the version, the generated API key, and the config path when it
finishes.

## Options

| Invocation | Effect |
|---|---|
| `sudo bash install.sh` | Install: download the latest release, verify it, install and start the service. |
| `sudo bash install.sh --uninstall` | Remove the service and binary. **Keep** `/etc/runbound` and `/var/lib/runbound`. |
| `sudo bash install.sh --purge` | Remove everything: service, binary, config, data, and the `runbound` user/group. |
| `bash install.sh --help` | Print usage and exit (no root needed, installs nothing). |

Piped form: append `-s -- <option>`, e.g.
`curl -fsSL .../install.sh | sudo bash -s -- --purge`.

## What the installer does

1. **Architecture** — detects `x86_64` / `aarch64`; aborts on anything else.
2. **Latest release** — queries the GitHub API for the latest tag, downloads
   `runbound-<arch>-linux-musl` (with a GitHub-API asset fallback if the direct URL fails).
3. **Integrity** — see [below](#integrity-verification). Aborts on a SHA256 mismatch or a
   failed minisign check.
4. **User & directories** — creates the `runbound` system user and group (no login), and
   `0750` `/etc/runbound` and `/var/lib/runbound`.
5. **Binary** — installs to `/usr/local/sbin/runbound` (`0755`, owned by root).
6. **Default config** — writes `/etc/runbound/runbound.conf` **only if it does not already
   exist** (an upgrade never overwrites your config). Defaults: listen on `0.0.0.0:53`,
   forward to `1.1.1.1` / `1.0.0.1` over DNS-over-TLS, allow RFC-1918 + loopback, refuse the
   rest, `rate-limit: 200`.
7. **API key** — generates a random key into `/etc/runbound/env` as `RUNBOUND_API_KEY`
   (via `openssl`, falling back to `/dev/urandom`), **only if the file does not exist**.
8. **Service** — installs a hardened `runbound.service` (`NoNewPrivileges`,
   `ProtectSystem=strict`, capability set `CAP_NET_BIND_SERVICE`/`NET_RAW`/`NET_ADMIN`/
   `BPF`/`PERFMON` granted **by default** — XDP is the default build feature and
   resolution path, so the wider set is needed out of the box; a minimal
   `CAP_NET_BIND_SERVICE`-only set is available as a commented opt-in for `xdp: no`
   deployments that want to shrink the capability set), then `enable` + `start`, and
   verifies it is active.

Re-running the installer upgrades the binary and service to the latest release while keeping
your existing config and API key.

## Integrity verification

The installer verifies the downloaded binary automatically:

- **SHA256** against the release `SHA256SUMS` — enforced whenever `sha256sum` and the
  checksums file are available; a mismatch (or a missing entry) aborts the install.
- **minisign signature** of `SHA256SUMS` against the embedded public key — performed when
  `minisign` is installed. A failed signature aborts the install. If `minisign` is not
  installed, this step is skipped with a warning (the SHA256 check still runs).

To verify a release **manually** (e.g. before piping to a shell), see [BUILD.md](BUILD.md):

```bash
# checksums
sha256sum -c SHA256SUMS --ignore-missing

# signature (public key)
minisign -Vm SHA256SUMS -P "RWSBM9HzDiZpfCD82uTnkeP1Ui30LfWE96C8EtFyI4/WVyLAVxpLzYy/"
```

## File locations

| Path | Purpose |
|---|---|
| `/usr/local/sbin/runbound` | The binary. |
| `/etc/runbound/runbound.conf` | Main configuration (unbound-style syntax). |
| `/etc/runbound/env` | `RUNBOUND_API_KEY=…` (loaded by the service, mode `0640`). |
| `/var/lib/runbound/` | Runtime data (e.g. the persistent IP blacklist). |
| `/etc/systemd/system/runbound.service` | The systemd unit. |

## After install

- **API key:** `grep RUNBOUND_API_KEY /etc/runbound/env`
- **Health:** `curl -H "Authorization: Bearer <key>" http://127.0.0.1:8080/health`
- **Logs:** `journalctl -u runbound -f`
- **XDP status:** `journalctl -u runbound | grep XDP`

Useful environment variables (set in `/etc/runbound/env`):

| Variable | Effect |
|---|---|
| `RUNBOUND_API_KEY` | API authentication key (set by the installer). |
| `RUNBOUND_DISABLE_XDP=1` | Emergency escape hatch — start without attaching XDP (use if the host became unreachable after an XDP attach). |
| `RUNBOUND_NO_RECVMMSG=1` | Disable the batched `recvmmsg` receive on the kernel slow path. |

## Port 53 conflicts

If another resolver holds `:53`, the installer stops before changing anything and prints the
service name and the command to run, for example:

```bash
sudo systemctl disable --now systemd-resolved
# then point /etc/resolv.conf at a real nameserver:
echo 'nameserver 1.1.1.1' | sudo tee /etc/resolv.conf
```

Then re-run the install command.

## Uninstall vs purge

```bash
# keep config + data
curl -fsSL https://raw.githubusercontent.com/redlemonbe/Runbound/main/install.sh | sudo bash -s -- --uninstall

# remove config + data + the runbound user/group
curl -fsSL https://raw.githubusercontent.com/redlemonbe/Runbound/main/install.sh | sudo bash -s -- --purge
```

## Troubleshooting

- **Service will not start:** `journalctl -u runbound -n 50`. The most common cause is
  another process on `:53` — check `ss -ulpn | grep :53`.
- **Host unreachable after enabling XDP:** set `RUNBOUND_DISABLE_XDP=1` in `/etc/runbound/env`
  and `systemctl restart runbound`. See [xdp.md](xdp.md).
- **Empty/invalid API key:** delete `/etc/runbound/env` and re-run the installer to
  regenerate it.
