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

## Recommendations for production

1. **PIN via env var** — never put `hsm-pin:` in the config file. Use
   `/etc/runbound/env` (chmod 640) loaded by the systemd unit.

2. **YubiHSM 2** is the recommended production device (~100 €, USB, FIPS 140-2 L3).
   It supports up to 256 HMAC/signing operations per second, more than enough for
   Runbound's startup-only key extraction.

3. **Key rotation** — generate a new key object in the HSM under a new label,
   update the config, and restart Runbound. The old label and key can be deleted
   from the HSM once the new key is confirmed working.

4. **Audit log** — HSMs maintain an internal hardware audit log of all key access
   operations. On YubiHSM 2, retrieve it with `yubihsm-shell > list log-entries`.

5. **Backup** — export a wrapped (encrypted) copy of the key under a backup wrap
   key and store offline. Without a backup, losing the HSM means regenerating
   the API key and re-HMAC-ing all store files.
