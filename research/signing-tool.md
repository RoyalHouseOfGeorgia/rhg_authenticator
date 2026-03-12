# YubiKey Signing Tool Research

## Ed25519 Signing via YubiKey 5C PIV

### Requirements
- **YubiKey firmware:** 5.7.0+ (Ed25519 support in PIV)
- **yubico-piv-tool:** 2.4.0+ (Ed25519 algorithm flag)
- **PIV slot:** 9c (Digital Signature)

### Signing Command

```bash
yubico-piv-tool -a verify-pin -a sign-data -s 9c -A ED25519 -P <PIN> -i data.bin -o signature.bin
```

- **Input:** Raw bytes (the canonical JSON payload). No pre-hashing — Ed25519 handles SHA-512 internally per RFC 8032.
- **Output:** Raw 64-byte signature (R || S). NOT DER-wrapped. (Needs empirical verification with real device.)

### PIN Retry Query

```bash
ykman piv info | grep "PIN tries remaining"
# Output: "PIN tries remaining: 3/3"
```

No standalone retries command — parse from `ykman piv info`.

### Key Export (Public Key)

```bash
yubico-piv-tool -a read-certificate -s 9c | openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | base64
```

Or if a self-signed cert was generated during key setup:

```bash
ykman piv certificates export 9c - | openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | base64
```

Output: 44-byte Base64 string (12-byte SPKI header + 32-byte raw Ed25519 key).

### DER Public Key Format

| Offset | Length | Content |
|--------|--------|---------|
| 0 | 12 | SPKI ASN.1 header: `302a300506032b6570032100` |
| 12 | 32 | Raw Ed25519 public key |

The library's `decodePublicKey` strips the 12-byte prefix automatically.

## QR Code Byte Budget

### URL Structure

```
https://verify.royalhouseofgeorgia.ge/?p=[B64URL]&s=[B64URL]
```

### Capacity at Error Correction Level Q

| QR Version | Modules | Byte-Mode Capacity |
|------------|---------|-------------------|
| 16 | 81x81 | 322 bytes |
| 17 | 85x85 | 364 bytes |
| 18 | 89x89 | 394 bytes |

### Budget Breakdown (Version 18-Q, 394 chars max)

- Domain + path: `https://verify.royalhouseofgeorgia.ge/?p=` = ~43 chars
- Signature param: `&s=` + 86-char Base64URL (64 bytes) = ~89 chars
- **Fixed overhead:** ~132 chars
- **Remaining for payload Base64URL:** ~262 chars = ~196 raw bytes

### Printability

At 4cm print size with Version 18 (89 modules + 8 quiet zone = 97 units):
- Module size: 40mm / 97 = 0.41mm
- ISO minimum: 0.33mm
- Confirmed scannable.

### Note on ykman vs yubico-piv-tool

- `ykman piv` handles key management (generate, import, export, info) but **cannot sign arbitrary data**.
- `yubico-piv-tool` is required for the actual signing operation (`sign-data` action).
- Both tools are part of the Yubico toolchain and can coexist.

## Secret Scanning Recommendation

Install gitleaks as a pre-commit hook:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2  # update periodically
    hooks:
      - id: gitleaks
```

Requires Python `pre-commit` package. Alternative: run `gitleaks detect` as a standalone git hook script (no Python dependency).
