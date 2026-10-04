# Security

This is an educational/reference implementation, pending independent security review. Current unit tests are not evidence that every provider is ready for production.

- Callers explicitly allow algorithms; an untrusted header cannot select them alone.
- Unsecured `none` requires explicit opt-in.
- HMAC key size is at least the digest output size; RSA signing keys are at least 2048 bits.
- JWS verification uses original encoded segments and processes `crit` and `b64=false` explicitly.
- Cryptographic verification and JWT application claim validation are separate.
- JWE binds the protected header as AEAD additional authenticated data, and decryption requires allowed key/content algorithms.
- RSA1_5 is a known registry identifier without an enabled provider.

Do not publish private keys or production tokens in issues. For private reports, use GitHub private vulnerability reporting if enabled, or contact the maintainer through an existing private channel. [Русская версия](SECURITY.ru.md).
