# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |
| < 1.0   | No        |

## Reporting Vulnerabilities

Please report security vulnerabilities to **security@theqrl.org**.

Do not open public issues for security vulnerabilities.

---

## Security Model

### Cryptographic Primitives

wallet.js uses **ML-DSA-87** (FIPS 204) for digital signatures via the `@theqrl/mldsa87` package.

| Property | Value |
|----------|-------|
| Security Level | NIST Level 5 (256-bit classical) |
| Public Key Size | 2,592 bytes |
| Secret Key Size | 4,896 bytes |
| Signature Size | 4,627 bytes |

### Key Derivation

```
Seed (48 bytes, random)
    │
    ├── SHA-256 ──► ML-DSA-87 KeyGen ──► (pk, sk)
    │
    └── Descriptor (3 bytes) + Seed ──► Extended Seed (51 bytes)
                                              │
                                              └── Mnemonic (34 words)
```

### Address Derivation

```
Address = SHAKE-256(Descriptor || PublicKey, addressSize bytes)
```

The address length is **configurable** via the `addressSize` parameter. The
default for this migration is 64 bytes.

| Size     | Constant                   | Post-Quantum Category | String form (with `Q`) |
|----------|----------------------------|-----------------------|------------------------|
| 20 bytes | `ADDRESS_SIZE_CATEGORY_1`  | NIST Category 1       | 41 chars               |
| 64 bytes | `ADDRESS_SIZE_CATEGORY_5`  | NIST Category 5       | 129 chars              |

**Default: 64 bytes (NIST Category 5).** This aligns address length with the
64-byte QRL address migration. Callers that need legacy vectors should pass an
explicit address size.

```javascript
import { MLDSA87, ADDRESS_SIZE_CATEGORY_1 } from '@theqrl/wallet.js';

// Default — 64-byte (Cat 5) addresses:
const w = MLDSA87.newWallet();

// Explicit legacy 20-byte derivation:
const wLegacy = MLDSA87.newWallet([0, 0], ADDRESS_SIZE_CATEGORY_1);
```

All `Wallet` factory methods (`newWallet`, `newWalletFromSeed`,
`newWalletFromExtendedSeed`, `newWalletFromMnemonic`) accept an optional
trailing `addressSize` argument; the standalone
`getAddressFromPKAndDescriptor(pk, descriptor, addressSize?)` helper accepts
the same parameter.

**Security trade-off.** SHAKE-256 is an extendable-output function, so the
20-byte address is literally the first 40 hex characters of the corresponding
64-byte address for the same (descriptor, pk). The choice is about how much
collision resistance the address itself provides; the underlying signature
scheme's strength is unchanged.

- At 20 bytes (160 bits): ≈80-bit classical / ≈53-bit quantum collision
  resistance — consistent with v2.x behavior and sufficient for applications
  that rely on application-layer checksums or out-of-band address confirmation.
- At 64 bytes (512 bits): ≈256-bit classical / ≈128-bit quantum collision
  resistance under Grover-style search, keeping address collision resistance
  aligned with NIST Category 5 targets.

Addresses are displayed with a `Q` prefix in lowercase hexadecimal, always
2 × `addressSize` hex characters long.

---

## Mnemonic Security

### No Built-in Checksum

**Important:** Unlike BIP39, QRL mnemonics do not include a checksum for error detection.

**Implications:**
- A typo in a mnemonic word may still produce a valid (but different) wallet
- User errors during backup or restore cannot be detected by the library
- Example: "absorb" and "absent" are both valid words - swapping them produces a different wallet

**Recommended Application-Level Mitigations:**

1. **Address Verification on Restore:**
   Store a hash of the expected address alongside the encrypted mnemonic in wallet files:
   ```javascript
   // When creating wallet
   const wallet = MLDSA87.newWallet();
   const addressHash = sha256(wallet.getAddress());
   saveWalletFile({ encryptedMnemonic, addressHash });

   // When restoring wallet
   const restored = MLDSA87.newWalletFromMnemonic(mnemonic);
   const restoredHash = sha256(restored.getAddress());
   if (!constantTimeEqual(restoredHash, expectedHash)) {
     throw new Error('Mnemonic does not match expected wallet');
   }
   ```

2. **Full Address Verification:**
   Wherever addresses are displayed or confirmed — wallet restore, transaction signing, address book entries — always show the **complete** address. Do not truncate to first/last characters — address-poisoning and dusting attacks exploit partial matching to trick users into confirming an attacker-controlled address.

---

## Address Security

### No Built-in Checksum

**Important:** QRL addresses do not include a checksum (unlike EIP-55 mixed-case encoding in Ethereum). `isValidAddress()` only checks the structural format — `Q` prefix followed by an even number of lowercase/uppercase hex characters — it cannot detect a mistyped or truncated address. Length is not fixed by the validator because 20-byte, 64-byte, and future addresses coexist; consumers that require a specific length should check `stringToAddress(addr).length` after validation.

**Implications:**
- Any `Q` + even-length hex string passes structural validation
- A single character error produces a valid but unrelated address
- Funds sent to a mistyped address are unrecoverable

**Recommended Application-Level Mitigations:**

1. **Address Book / Whitelist:**
   Maintain a list of known-good addresses and warn users when sending to an address not in their address book.

2. **Full Address Verification:**
   Always display the **complete** address and require explicit user confirmation before signing a transaction. Never truncate to first/last characters — address-poisoning and dusting attacks deliberately generate addresses that match a target's prefix and suffix to exploit partial visual checks.

3. **Application-Layer Checksums:**
   Applications that store or transmit addresses may add their own checksum envelope (e.g. CRC32, Base58Check, or Bech32) to detect transcription errors before submitting a transaction. This is intentionally left to the application layer so that different transports can choose the scheme best suited to their context.

4. **Second-Step Verification:**
   For high-value transactions, implement a secondary confirmation channel (e.g. displaying the address on a separate device, QR code cross-check, or out-of-band confirmation) to guard against clipboard hijacking and address substitution attacks.

---

## Seed Derivation

ML-DSA-87 (FIPS 204) requires a 32-byte seed for key generation. QRL uses a 48-byte seed for mnemonic compatibility across wallet types. The seed is hashed with SHA-256 to derive the required 32-byte ML-DSA seed:

```
48-byte QRL Seed → SHA-256 → 32-byte ML-DSA-87 Seed → Key Generation
```

This is by design for FIPS 204 compliance and go-qrllib cross-implementation compatibility. The 256-bit entropy in the derived seed provides full security for ML-DSA-87's NIST Level 5.

---

## Sensitive Data

### Assets to Protect

| Asset | Sensitivity | Notes |
|-------|-------------|-------|
| Secret Key | Critical | Never expose; can sign arbitrary messages |
| Seed | Critical | Can derive secret key |
| Extended Seed | Critical | Contains seed |
| Mnemonic | Critical | Human-readable extended seed |
| Public Key | Public | Safe to share |
| Address | Public | Safe to share |

### Memory Security

**Important:** JavaScript does not provide guaranteed secure memory handling.

1. **Call `zeroize()` when done:**
   ```javascript
   const wallet = MLDSA87.newWallet();
   // ... use wallet ...
   wallet.zeroize(); // Overwrites sk, seed, extendedSeed with zeros
   ```

2. **Limitations:**
   - JavaScript's garbage collector may retain copies
   - JIT compilation may create additional copies
   - This provides best-effort protection, not cryptographic guarantees

3. **Recommendations:**
   - Minimize wallet lifetime in memory
   - Avoid logging or serializing sensitive data
   - Consider hardware security modules for high-value applications

### Accidental Leakage Hardening

Any in-process code holding a `Wallet` reference already has full signing
authority, so private fields cannot raise that security boundary. What the
library *does* defend against is **accidental** leakage of raw secret
material through logs, crash reporters, telemetry, devtools, and generic
object-traversal code:

| Surface | Protection |
|---------|------------|
| `Object.keys(wallet)` / `{...wallet}` | Secret-bearing fields (`sk`, `seed`, `extendedSeed`, `_zeroized`) are defined as **non-enumerable**, so reflection-based traversal does not surface them. Only `descriptor` and `pk` (public material) remain enumerable. |
| `JSON.stringify(wallet)` | `Wallet.toJSON()` returns only a redacted public shape: `{ address, pk }`. Raw `sk`, `seed`, and `extendedSeed` are never serialized. |
| `Seed` / `ExtendedSeed` `JSON.stringify` | Both types define `toJSON()` returning `{ type, redacted: true }` — raw `bytes` are never serialized. The `bytes` field is also non-enumerable. |
| `console.log(wallet)` / `util.inspect(wallet)` | A custom `Symbol.for('nodejs.util.inspect.custom')` method returns `Wallet { address: '…', state: 'live' \| 'zeroized', <secret material redacted> }`. `Seed` and `ExtendedSeed` render as `<redacted>`. |

Direct property access (`wallet.sk`, `seed.bytes`, etc.) still works for
legitimate callers — non-enumerable means *not traversed by default*, not
*inaccessible*. The supported, auditable API remains `getSK()`, `getSeed()`,
`getExtendedSeed()`, `getMnemonic()`, and `zeroize()`.

**This is defense-in-depth, not a trust boundary.** An adversary with a
wallet reference can still call `sign()`, `getSK()`, or reflect through
`Object.getOwnPropertyNames()`. Follow the recommendations above to limit
the window in which a live `Wallet` exists.

---

## Input Validation

### Validated Inputs

| Function | Validation |
|----------|------------|
| `new Seed(bytes)` | Exactly 48 bytes |
| `new ExtendedSeed(bytes)` | Exactly 51 bytes, valid wallet type |
| `new Descriptor(bytes)` | Exactly 3 bytes, valid wallet type |
| `wallet.sign(message)` | message is Uint8Array |
| `MLDSA87.verify(sig, msg, pk)` | All inputs are Uint8Array of correct lengths |
| `stringToAddress(str)` | Starts with Q, 128 hex characters |

### Error Handling

All validation errors throw `Error` with descriptive messages. Wrap wallet operations in try-catch:

```javascript
try {
  const wallet = MLDSA87.newWalletFromMnemonic(userInput);
} catch (e) {
  console.error('Invalid mnemonic:', e.message);
}
```

**Design Note:** Input validation functions (`isValidAddress`, etc.) return boolean. Data conversion and cryptographic functions throw on invalid input. Signature verification returns boolean (true/false) without leaking timing information about why verification failed.

---

## Randomness

Seed generation uses the Web Crypto API exclusively (`globalThis.crypto.getRandomValues`). This is a cryptographically secure random number generator available in both Node.js (20.19+) and modern browsers.

An additional sanity check rejects output that is all zeros for buffers of 16 bytes or more.

---

## Side-Channel Resistance

Timing side-channel resistance depends on the underlying `@theqrl/mldsa87` implementation.

### Constant-Time Verification

Signature verification uses constant-time comparison to prevent timing attacks:

```javascript
// From @theqrl/mldsa87 cryptoSignVerify:
let diff = 0;
for (i = 0; i < CTILDEBytes; ++i) {
  diff |= c[i] ^ c2[i];
}
return diff === 0;
```

### Timing Considerations for Arithmetic Operations

The Montgomery reduction and other arithmetic operations in `@theqrl/mldsa87` use JavaScript's `BigInt` type. **Important**: The JavaScript specification does not guarantee that `BigInt` operations are constant-time. The execution time of operations like multiplication and division may vary based on operand values.

**Implications:**
- Signing operations that use these arithmetic functions may have timing variations
- This is a known limitation of JavaScript cryptographic implementations
- Signature verification uses constant-time comparison (see above), which is the critical path for timing attacks

**Mitigations for sensitive deployments:**
- For applications with strict constant-time requirements, consider using the Go implementation ([go-qrllib](https://github.com/theQRL/go-qrllib)) which provides better timing guarantees
- Rate-limit signature operations at the application layer to reduce timing attack feasibility
- Run signing operations in isolated environments where timing cannot be observed

---

## Dependencies

| Package | Purpose | Security Notes |
|---------|---------|----------------|
| `@theqrl/mldsa87` | ML-DSA-87 signatures | Audited; FIPS 204 compliant |
| `@noble/hashes` | SHA-256, SHAKE-256 | Widely audited; constant-time |

---

## Best Practices

### Do

- Call `zeroize()` when wallet is no longer needed
- Validate addresses before sending transactions
- Use `isValidAddress()` for user-provided addresses
- Keep mnemonic backups offline and encrypted
- Use hardware wallets for high-value holdings

### Don't

- Log or print secret keys, seeds, or mnemonics
- Store unencrypted mnemonics in databases or files
- Transmit seeds/mnemonics over networks
- Reuse seeds across different applications
- Ignore validation errors

---

## Audit Status

This library has been security audited. See the [internal audit](https://github.com/theQRL/internal-audit/tree/main/wallet.js) for details.

| Category | Issues Found | Status |
|----------|--------------|--------|
| Critical | 1 | Fixed |
| High | 2 | Fixed |
| Medium | 1 | Fixed |

---

## Supply Chain Security

### npm Provenance

All npm packages are published with [npm provenance](https://docs.npmjs.com/generating-provenance-statements), which cryptographically links published packages to their source repository and build workflow.

Verify provenance on npm:
```bash
npm audit signatures
```

### Sigstore Attestations

All releases include GitHub attestations backed by Sigstore:
- **Build provenance** for checksums and package files
- **SBOM attestations** in SPDX and CycloneDX formats
- **SLSA Level 3 provenance** for build verification

### Dependency Tracking

Each release includes Software Bill of Materials (SBOM) files:
- `sbom-spdx.json` - SPDX format
- `sbom-cyclonedx.json` - CycloneDX format

---

## Release Verification

All releases include cryptographic attestations and checksums for verification.

### Verifying with GitHub CLI

```bash
# Verify attestations for package files
gh attestation verify package.json --owner theQRL
gh attestation verify package-lock.json --owner theQRL

# Verify SBOM attestation
gh attestation verify sbom-spdx.json --owner theQRL
```

### Verifying Checksums

Download and verify checksums from the release:

```bash
# Download checksums file
curl -LO https://github.com/theQRL/wallet.js/releases/download/vX.Y.Z/checksums-sha256.txt

# Verify package files
sha256sum -c checksums-sha256.txt
```

### Verifying SLSA Provenance

```bash
# Install slsa-verifier: https://github.com/slsa-framework/slsa-verifier#installation

# Download provenance
curl -LO https://github.com/theQRL/wallet.js/releases/download/vX.Y.Z/provenance.intoto.jsonl

# Verify provenance
slsa-verifier verify-artifact package.json \
  --provenance-path provenance.intoto.jsonl \
  --source-uri github.com/theQRL/wallet.js
```

### Software Bill of Materials (SBOM)

Each release includes SBOMs in two formats:
- **SPDX**: `sbom-spdx.json`
- **CycloneDX**: `sbom-cyclonedx.json`

These can be analyzed with tools like:
```bash
# Using grype for vulnerability scanning
grype sbom:sbom-spdx.json

# Using syft for inspection
syft convert sbom-cyclonedx.json -o table
```

### What Gets Attested

| Artifact | Attestation Type | Purpose |
|----------|-----------------|---------|
| `package.json`, `package-lock.json` | Build provenance | Verify package dependencies |
| `checksums-sha256.txt` | Build provenance | Integrity verification |
| `sbom-spdx.json` | SBOM | Software composition |
| `sbom-cyclonedx.json` | SBOM | Software composition |
| Source code | SLSA provenance | Build reproducibility |
| npm package | npm provenance | Package authenticity |

### Trust Model

Attestations are signed using GitHub's Sigstore integration:
- **Identity**: GitHub Actions OIDC token
- **Transparency**: Logged in Sigstore's Rekor transparency log
- **Verification**: Proves release came from official CI workflow
