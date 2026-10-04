# Implementation matrix

Легенда:

- **crypto** — wire format и crypto operation подключены;
- **model** — идентификатор/структура известны, но crypto backend отсутствует;
- **disabled** — намеренно не включено в baseline API.

## JWS Algorithms

| Algorithm | Status |
| --- | --- |
| HS256 / HS384 / HS512 | crypto |
| RS256 / RS384 / RS512 | crypto |
| PS256 / PS384 / PS512 | crypto |
| ES256 / ES384 / ES512 | crypto |
| ES256K | crypto |
| Ed25519 | crypto |
| none | crypto, explicit opt-in only |
| EdDSA | model; deprecated identifier |
| Ed448 | model |
| ML-DSA-44 / 65 / 87 | model |

## JWE Key Management

| Algorithm | Status |
| --- | --- |
| dir | crypto |
| RSA-OAEP | crypto |
| RSA-OAEP-256 / 384 / 512 | crypto |
| RSA1_5 | disabled |
| A128KW / A192KW / A256KW | model |
| ECDH-ES and ECDH-ES+AES-KW | model |
| AES-GCM-KW | model |
| PBES2 | model |

## JWE Content Encryption

| Algorithm | Status |
| --- | --- |
| A128GCM | crypto |
| A256GCM | crypto |
| A192GCM | model |
| A128CBC-HS256 | model |
| A192CBC-HS384 | model |
| A256CBC-HS512 | model |

## Serialization

| Format | Status |
| --- | --- |
| JWS Compact | operational API |
| JWS Flattened JSON | data model |
| JWS General JSON | data model |
| JWE Compact | operational API for implemented crypto suites |
| JWE Flattened JSON | data model |
| JWE General JSON | data model |
