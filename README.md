# localzet-jose

Educational/reference JOSE library in Rust: JWS, JWE, JWK and JWT. This is an unfinished continuation of [JWT](https://github.com/localzet/JWT) and [LWT](https://github.com/localzet/LWT), grouped by `localzet-tokens`. [Полная документация на русском](README.ru.md).

Cryptographic primitives come from RustCrypto crates; the library implements JOSE framing, signing input, key/claims models and explicit verification policies. It is not an audited replacement for a mature production library.

## Implemented scope

- JWS compact serialization, detached payload, RFC 7797 `b64=false`, critical-header handling and explicit algorithm allow-lists.
- HMAC SHA-256/384/512; RSA PKCS#1 v1.5/PSS; ECDSA P-256/P-384/P-521/secp256k1; Ed25519. Unsecured `none` requires a separate explicit opt-in.
- JWE compact framing with `dir` or RSA-OAEP variants and A128GCM/A256GCM. Decryption requires explicit `alg`/`enc` allow-lists.
- JWK/JWK Set models, key ID selection, symmetric key extraction and RFC 7638 thumbprints.
- Typed registered JWT claims with preserved additional claims. Cryptographic verification and application claim validation are separate operations.
- Registry snapshots preserve unknown future identifiers. An identifier in the registry does not imply a working cryptographic provider.

JSON serialization has data models, rather than complete signing/decryption APIs. RSA1_5, Ed448, ML-DSA, AES-KW, ECDH-ES, PBES2, CBC-HMAC and A192GCM remain unsupported cryptographic operations.

## Use

```bash
cargo test --locked --all-targets
cargo run --locked --example hs256
```

```rust
let policy = VerificationPolicy::new().allow_algorithm("Ed25519");
let verified = jwt::verify(token, &key, &policy, &claims_validation)?;
```

Caller policy, provider algorithm and key type must agree. Never derive trust solely from the token's `alg`. Review [SECURITY.md](SECURITY.md) before integration.

## Toolchain and status

Rust 1.85 is required by locked dependencies; the old 1.75 declaration was inaccurate. Local tests were run on Rust 1.98.1. CI checks 1.85 and 1.98.1. Clippy runs with warnings visible; deprecated GenericArray usage and existing style warnings are still pending.

The current tests cover compact and detached HMAC signing, JWT round trips and explicit rejection of unsecured signatures without opt-in. They do not establish interoperability of every listed provider.

## Next work

1. RFC 7520 vectors, negative algorithm/key confusion tests and parser fuzzing.
2. Complete JSON serialization APIs and JWK-to-provider key import.
3. Add AES-KW/ECDH-ES/PBES2 only with interoperability coverage.
4. Review key lifetime, secret storage and errors before production use.

License: [AGPL-3.0-or-later](LICENSE).
