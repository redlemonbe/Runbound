# HSM Key Storage (PKCS#11)

Runbound can load sensitive key material — the REST API Bearer token and the JSON
store HMAC key — from a Hardware Security Module via PKCS#11. When enabled, keys
are never written to disk in plaintext and are physically non-extractable from the
hardware.

---

## Why HSM

| Property | Env var / config file | HSM |
|---|:---:|:---:|
| Key survives disk theft | ❌ | ✅ |
| Key protected against memory dump | ❌ | ✅ |
| Physical extraction impossible | ❌ | ✅ |
| Hardware audit log | ❌ | ✅ |
| FIPS 140-2 / 140-3 compliance path | ❌ | ✅ (device-dependent) |

In Runbound's PKCS#11 integration, keys are **extracted** from the HSM at startup
into `Zeroizing<T>` buffers (memory is scrubbed on process exit). The HSM session
is closed immediately after extraction — the HSM is not required to be reachable
during normal operation.

To prevent key extraction entirely (never leave the HSM), use a PKCS#11 token that
refuses `CKA_EXTRACTABLE=true` and perform all cryptographic operations inside the
HSM. This requires a custom integration beyond what Runbound currently provides
out of the box.

---

## Tested HSMs

| Device | Form factor | FIPS | Notes |
|---|---|:---:|---|
| **SoftHSM2** | Software (dev/CI only) | ❌ | Free, no hardware needed |
| **YubiHSM 2** | USB (~100 €) | FIPS 140-2 L3 | Recommended for production |
| **Nitrokey HSM 2** | USB (~50 €) | CC EAL 5+ | Open hardware, PKCS#11 via OpenSC |
| **AWS CloudHSM** | Cloud | FIPS 140-2 L3 | `cloudhsm_pkcs11.so` |
| **Thales Luna** | Network | FIPS 140-3 L3 | Enterprise; `libCryptoki2_64.so` |

Any PKCS#11-compliant HSM with a Linux `.so` driver should work.

---

## Prerequisites

```bash
# SoftHSM2 (for development and CI):
apt install softhsm2 opensc

# YubiHSM 2:
apt install yubihsm-connector yubihsm-shell
# or download the YubiHSM PKCS#11 SDK from Yubico

# Nitrokey HSM 2:
apt install opensc     # provides /usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so
                       # and sc-hsm-tool for token initialisation
```

---

## SoftHSM2 setup (development)

```bash
# 1. Initialise a token in slot 0
softhsm2-util --init-token --slot 0 \
    --label "runbound-dev" \
    --so-pin 000000 \
    --pin 1234

# Verify:
softhsm2-util --show-slots
# Token in slot 0:
#   Label: runbound-dev
#   Initialized: yes

# 2. Import the API key as a secret key object
#    (must be valid UTF-8; Runbound will use it as a Bearer token)
API_KEY=$(openssl rand -hex 32)
echo -n "$API_KEY" | pkcs11-tool \
    --module /usr/lib/softhsm/libsofthsm2.so \
    --login --pin 1234 \
    --write-object /dev/stdin \
    --type secretkey --key-type generic:32 \
    --label "runbound-api-key" \
    --extractable

# 3. Import the store HMAC key (32 random bytes)
openssl rand -out /tmp/store.key 32
pkcs11-tool \
    --module /usr/lib/softhsm/libsofthsm2.so \
    --login --pin 1234 \
    --write-object /tmp/store.key \
    --type secretkey --key-type generic:32 \
    --label "runbound-store-key" \
    --extractable
rm -f /tmp/store.key

# 4. Verify both objects are visible
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
    --login --pin 1234 --list-objects
# Object 0: type=secret-key  label=runbound-api-key
# Object 1: type=secret-key  label=runbound-store-key
```

---

## YubiHSM 2 setup (production)

The YubiHSM 2 PKCS#11 library is `libyubihsm_pkcs11.so` (from the Yubico SDK).

```bash
# 1. Start the YubiHSM connector daemon
yubihsm-connector &

# 2. Create a wrap key and an authentication key, then import secrets
yubihsm-shell
yubihsm> connect
yubihsm> session open 1 password   # default authkey ID 1
yubihsm> generate hmackey 0 "runbound-store-key" 1 sign-hmac hmac-sha256
yubihsm> put opaque 0 "runbound-api-key" 1 opaque-data $(openssl rand -hex 32)
yubihsm> session close 0
yubihsm> quit

# 3. Configure the PKCS#11 module
cat > /etc/yubihsm_pkcs11.conf <<EOF
# YubiHSM PKCS#11 connector
connector=http://127.0.0.1:12345
EOF
export YUBIHSM_PKCS11_CONF=/etc/yubihsm_pkcs11.conf
```

---

## Nitrokey HSM 2 setup (production)

The Nitrokey HSM 2 is a SmartCard-HSM in USB form. OpenSC provides the PKCS#11
driver at `/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so` and `sc-hsm-tool`
for token management.

```bash
# 1. Install OpenSC (if not already installed)
apt install opensc

# 2. Plug in the Nitrokey and verify the device is detected
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so \
    --list-slots
# Available slots:
# Slot 0 (0x0): Nitrokey Nitrokey HSM 2 ...
#   token state:   uninitialized

# 3. Initialise the token
#    SO-PIN: 16 hex chars (8 bytes) — factory default is 3537363231383830
#    PIN:    6+ digits
sc-hsm-tool --initialize \
    --so-pin 3537363231383830 \
    --pin 648219 \
    --label "runbound-prod"

# Verify — the token should now appear as initialized
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so \
    --list-slots
# Slot 0 (0x0): Nitrokey Nitrokey HSM 2 ...
#   token label:   runbound-prod
#   token state:   initialized

# 4. Import the API key
API_KEY=$(openssl rand -hex 32)
echo -n "$API_KEY" | pkcs11-tool \
    --module /usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so \
    --login --pin 648219 \
    --write-object /dev/stdin --id 01 \
    --type secretkey --key-type generic:32 \
    --label "runbound-api-key" \
    --extractable

# 5. Import the store HMAC key
openssl rand -out /tmp/store.key 32
pkcs11-tool \
    --module /usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so \
    --login --pin 648219 \
    --write-object /tmp/store.key --id 02 \
    --type secretkey --key-type generic:32 \
    --label "runbound-store-key" \
    --extractable
rm -f /tmp/store.key

# 6. Verify both objects
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so \
    --login --pin 648219 --list-objects
# Using slot 0 with a present token (0x0)
# Secret Key Object; unknown key algorithm 0
#   label:      runbound-api-key
#   ID:         01
# Secret Key Object; unknown key algorithm 0
#   label:      runbound-store-key
#   ID:         02
```

In `runbound.conf`, use the OpenSC library path:

```
server:
    hsm-pkcs11-lib:  /usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so
    hsm-slot:        0
    hsm-api-key-label:   runbound-api-key
    hsm-store-key-label: runbound-store-key
```

---

## Using SoftHSM2 in CI/CD

SoftHSM2 is the recommended HSM backend for automated tests and CI pipelines — it
requires no hardware and runs entirely in software.

Example GitHub Actions workflow:

```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install SoftHSM2 and OpenSC
        run: sudo apt-get install -y softhsm2 opensc

      - name: Configure SoftHSM2
        run: |
          mkdir -p /tmp/softhsm/tokens
          cat > /tmp/softhsm2.conf <<EOF
          directories.tokendir = /tmp/softhsm/tokens
          objectstore.backend = file
          EOF
          echo "SOFTHSM2_CONF=/tmp/softhsm2.conf" >> $GITHUB_ENV

      - name: Initialise token
        run: |
          softhsm2-util --init-token --slot 0 \
              --label "runbound-ci" \
              --so-pin 000000 \
              --pin 1234

      - name: Import API key and store HMAC key
        run: |
          API_KEY=$(openssl rand -hex 32)
          echo -n "$API_KEY" | pkcs11-tool \
              --module /usr/lib/softhsm/libsofthsm2.so \
              --login --pin 1234 \
              --write-object /dev/stdin \
              --type secretkey --key-type generic:32 \
              --label "runbound-api-key" \
              --extractable

          openssl rand -out /tmp/store.key 32
          pkcs11-tool \
              --module /usr/lib/softhsm/libsofthsm2.so \
              --login --pin 1234 \
              --write-object /tmp/store.key \
              --type secretkey --key-type generic:32 \
              --label "runbound-store-key" \
              --extractable
          rm -f /tmp/store.key

          # Expose the PIN to subsequent steps
          echo "HSM_PIN=1234" >> $GITHUB_ENV

      - name: Write Runbound test config
        run: |
          cat > /tmp/runbound-ci.conf <<EOF
          server:
              port:              5300
              hsm-pkcs11-lib:    /usr/lib/softhsm/libsofthsm2.so
              hsm-slot:          0
              hsm-api-key-label: runbound-api-key
              hsm-store-key-label: runbound-store-key
          forward-zone:
              name: "."
              forward-addr: 1.1.1.1
          EOF

      - name: Start Runbound and verify HSM active
        run: |
          ./target/release/runbound /tmp/runbound-ci.conf &
          sleep 2
          curl -sf http://localhost:8081/health \
            -H "Authorization: Bearer $HSM_PIN" | jq .hsm
          # → true
```

---

## Runbound configuration

```
server:
    # Path to the PKCS#11 shared library
    hsm-pkcs11-lib:  /usr/lib/softhsm/libsofthsm2.so

    # Slot index (0-based)
    hsm-slot:        0

    # PIN — prefer the env var below; hsm-pin in config emits WARN
    # hsm-pin:       1234

    # Label of the CKO_SECRET_KEY object used as the API Bearer token
    hsm-api-key-label:   runbound-api-key

    # Label of the CKO_SECRET_KEY object used as the store HMAC key
    hsm-store-key-label: runbound-store-key
```

Store the PIN securely:

```bash
cat > /etc/runbound/env <<'EOF'
HSM_PIN=1234
EOF
chmod 640 /etc/runbound/env
chown root:runbound /etc/runbound/env
```

In the systemd unit, load the env file:

```ini
[Service]
EnvironmentFile=/etc/runbound/env
```

---

## Key priority chain

| Priority | API key source | Store key source |
|---|---|---|
| 1 (highest) | HSM `hsm-api-key-label` | HSM `hsm-store-key-label` |
| 2 | `RUNBOUND_API_KEY` env var | `RUNBOUND_STORE_KEY` env var |
| 3 | `api-key:` in config | — |
| 4 (lowest) | Auto-generated (CSPRNG) | — (integrity disabled) |

When `hsm-pkcs11-lib` is set and key loading fails at startup, Runbound exits
immediately with an error message. There is no silent fallback — if you opt into
HSM protection, Runbound refuses to run without it.

---

## Startup behaviour

```
[INFO] Opening PKCS#11 HSM session  lib=/usr/lib/softhsm/libsofthsm2.so  slot=0
[INFO] HSM: API key loaded           label=runbound-api-key
[INFO] HSM: store HMAC key loaded    label=runbound-store-key
[INFO] HSM session closed — keys held in process memory
```

The HSM session is opened, keys are extracted into `Zeroizing<T>` buffers, and
the session is closed. The HSM does not need to remain connected after startup.

```bash
# Verify HSM is active
curl -s http://localhost:8081/health -H "Authorization: Bearer $KEY" \
  | jq .hsm
# true
```

---

## Object requirements

Runbound calls `C_GetAttributeValue(CKA_VALUE)` on each key object. The object
**must** have `CKA_EXTRACTABLE = true` to allow value extraction. On some HSMs
this is set at import time (`--extractable` flag for pkcs11-tool) and cannot be
changed afterwards.

On YubiHSM 2 and Luna, truly non-extractable objects can be used if you adapt
the integration to perform signing/HMAC inside the HSM rather than extracting
the raw bytes. This requires custom code beyond the current `src/hsm.rs`.

---

## Key rotation

### SoftHSM2

```bash
# 1. Import the new key under a new label
NEW_API_KEY=$(openssl rand -hex 32)
echo -n "$NEW_API_KEY" | pkcs11-tool \
    --module /usr/lib/softhsm/libsofthsm2.so \
    --login --pin 1234 \
    --write-object /dev/stdin \
    --type secretkey --key-type generic:32 \
    --label "runbound-api-key-v2" \
    --extractable

# 2. Update the config to point to the new label
sed -i 's/hsm-api-key-label:.*/hsm-api-key-label: runbound-api-key-v2/' \
    /etc/runbound/runbound.conf

# 3. Reload (SIGHUP replaces zones but not HSM keys — restart is required)
systemctl restart runbound

# 4. Verify the new key is active
curl -s http://localhost:8081/health \
    -H "Authorization: Bearer $NEW_API_KEY" | jq .hsm
# true

# 5. Delete the old key object once the new one is confirmed working
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
    --login --pin 1234 \
    --delete-object --type secretkey --label "runbound-api-key"
```

### YubiHSM 2

```bash
# 1. Import the new key under a new ID in yubihsm-shell
yubihsm-shell
yubihsm> connect
yubihsm> session open 1 password
yubihsm> put opaque 0 "runbound-api-key-v2" 1 opaque-data $(openssl rand -hex 32)
# Note the new object ID returned, e.g. 0x0003
yubihsm> session close 0
yubihsm> quit

# 2. Update the config and restart
sed -i 's/hsm-api-key-label:.*/hsm-api-key-label: runbound-api-key-v2/' \
    /etc/runbound/runbound.conf
systemctl restart runbound

# 3. Verify
curl -s http://localhost:8081/health \
    -H "Authorization: Bearer $NEW_API_KEY" | jq .hsm
# true

# 4. Delete the old object
yubihsm-shell
yubihsm> connect
yubihsm> session open 1 password
yubihsm> delete 0 0x0001 opaque-data   # replace 0x0001 with the old object ID
yubihsm> session close 0
yubihsm> quit
```

The same procedure applies to `runbound-store-key` / `hsm-store-key-label`.

---

## Key backup and recovery

### SoftHSM2

SoftHSM2 stores tokens as files on disk, encrypted under the SO-PIN.

```bash
# 1. Locate the token directory
grep tokendir /etc/softhsm2.conf /usr/share/softhsm/softhsm2.conf 2>/dev/null
# directories.tokendir = /var/lib/softhsm/tokens

# 2. Copy the entire token directory offline
#    The files are encrypted by the SO-PIN — safe to store on untrusted media
cp -a /var/lib/softhsm/tokens /mnt/backup/softhsm-tokens-$(date +%Y%m%d)/

# Restore on a new system:
apt install softhsm2
cp -a /mnt/backup/softhsm-tokens-YYYYMMDD /var/lib/softhsm/tokens
# Update softhsm2.conf to point at the restored directory, then start Runbound
```

### YubiHSM 2

YubiHSM 2 supports hardware-encrypted wrapped exports. The wrap key never leaves
the device — only the wrapped (AES-256-CCM) payload is stored offline.

```bash
yubihsm-shell
yubihsm> connect
yubihsm> session open 1 password

# 1. Generate a dedicated wrap key (AES-256)
yubihsm> generate wrapkey 0 "backup-wrap" 1 export-wrapped,import-wrapped aes256-ccm96
# Returned ID e.g. 0x0002 — note it

# 2. Export each Runbound key object as a wrapped blob
yubihsm> export-wrapped 0 0x0002 opaque-data 0x0001 backup-api-key.enc
yubihsm> export-wrapped 0 0x0002 hmac-key    0x0003 backup-store-key.enc

yubihsm> session close 0
yubihsm> quit

# 3. Store backup-api-key.enc and backup-store-key.enc offline (USB, safe deposit)
#    They are AES-256-CCM encrypted and useless without the YubiHSM holding the wrap key
```

Restore on a replacement YubiHSM 2:

```bash
# The wrap key must be imported first on the new device,
# then the object blobs can be re-imported
yubihsm-shell
yubihsm> connect
yubihsm> session open 1 password
yubihsm> import-wrapped 0 0x0002 backup-api-key.enc
yubihsm> import-wrapped 0 0x0002 backup-store-key.enc
yubihsm> session close 0
yubihsm> quit
```

> **Warning:** Without a backup, losing the HSM requires regenerating the API key
> (via `POST /rotate-key` or config restart) and re-signing all store `.mac` files
> with the new HMAC key. All existing `.mac` integrity proofs become invalid.

---

## Troubleshooting

### Common startup errors

| Error message | Cause | Fix |
|---|---|---|
| `PKCS#11 error: C_Initialize failed: 0x00000003 (CKR_HOST_MEMORY)` | Library path incorrect or `.so` not installed | Check `hsm-pkcs11-lib`; run `ldd /path/to/lib.so` to verify dependencies |
| `CKR_PIN_INCORRECT` | Wrong PIN in `HSM_PIN` env var | Check `/etc/runbound/env`; verify `chmod 640` and correct value |
| `CKR_OBJECT_HANDLE_INVALID` | Label not found in the token | Run `pkcs11-tool --list-objects` to list actual labels; fix `hsm-api-key-label` |
| `CKA_EXTRACTABLE = false` | Object was imported without `--extractable` | Re-import the key with `--extractable`; cannot be changed after import |
| `runbound exited immediately after HSM config` | Fatal HSM error — no silent fallback | Check `journalctl -u runbound` for the specific PKCS#11 error code and fix before restarting |

### Diagnostic commands

```bash
# List available PKCS#11 slots and token state
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --list-slots

# List all objects in the token (requires PIN)
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
    --login --pin $HSM_PIN --list-objects

# Filter Runbound HSM log entries
journalctl -u runbound | grep -i HSM

# Check library dependencies (should show no missing .so)
ldd /usr/lib/softhsm/libsofthsm2.so

# For YubiHSM: verify connector is running
curl -s http://127.0.0.1:12345/connector/status
# {"status":"OK","serial":"...","version":"..."}
```

---

## Recommendations for production

1. **PIN via env var** — never put `hsm-pin:` in the config file. Use
   `/etc/runbound/env` (chmod 640) loaded by the systemd unit.

2. **YubiHSM 2** is the recommended production device (~100 €, USB, FIPS 140-2 L3).
   It supports up to 256 HMAC/signing operations per second, more than enough for
   Runbound's startup-only key extraction.

3. **Key rotation** — follow the step-by-step procedure in the
   [Key rotation](#key-rotation) section above. Import under a new label, update
   config, restart, verify `/health`, then delete the old object.

4. **Audit log** — HSMs maintain an internal hardware audit log of all key access
   operations. On YubiHSM 2, retrieve it with `yubihsm-shell > list log-entries`.

5. **Backup** — follow the procedure in the [Key backup and recovery](#key-backup-and-recovery)
   section above. For YubiHSM 2, use wrapped exports stored offline. For SoftHSM2,
   copy the encrypted token directory. Without a backup, losing the HSM requires
   regenerating all keys and re-signing all store integrity files.
