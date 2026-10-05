# localzet-jose

Учебная и reference-реализация семейства **JOSE** на Rust.

Цель проекта — реализовать механику JOSE самостоятельно, но не переписывать
криптографические примитивы. HMAC/RSA/ECDSA/Ed25519/AES-GCM предоставляются
отдельными Rust crypto crates, а serialization, signing input, policy,
JWK/JWT model и JOSE framing реализованы здесь.

## Архитектура

```text
localzet-jose
├── JWA
│   └── crypto providers
├── JWK
│   ├── JWK
│   ├── JWK Set
│   └── RFC 7638 thumbprint
├── JWS
│   ├── Compact Serialization
│   ├── Detached Payload
│   ├── RFC 7797 b64=false
│   └── JSON Serialization data model
├── JWE
│   ├── Compact Serialization
│   ├── dir + AES-GCM
│   ├── RSA key management + AES-GCM
│   └── JSON Serialization data model
└── JWT
    ├── Claims Set
    └── Claims validation
```

## Что реализовано

### JWS

Рабочие crypto providers:

- HS256
- HS384
- HS512
- RS256
- RS384
- RS512
- PS256
- PS384
- PS512
- ES256
- ES384
- ES512
- ES256K
- Ed25519
- `none` (только при явном opt-in; криптографической защиты не даёт)

Также реализованы:

- JWS Compact Serialization
- detached payload
- RFC 7797 `b64=false`
- General/Flattened JSON data model
- обязательная allow-list policy для verification
- `crit` handling

### JWE

Рабочие сочетания:

Key management:

- `dir`
- `RSA-OAEP`
- `RSA-OAEP-256`
- `RSA-OAEP-384`
- `RSA-OAEP-512`

Content encryption:

- `A128GCM`
- `A256GCM`

Также реализованы Compact Parsing, обязательная allow-list policy для `alg`/`enc` при decrypt и General/Flattened JSON data model.

### JWK

JWK хранит common parameters явно и специфичные параметры ключа без потерь.
Есть:

- `Jwk`
- `JwkSet`
- выбор по `kid`
- `oct` key extraction
- RFC 7638 SHA-256 thumbprint для `RSA`, `EC`, `OKP`, `oct`

### JWT

Семь registered claims RFC 7519 типизированы:

- `iss`
- `sub`
- `aud`
- `exp`
- `nbf`
- `iat`
- `jti`

Все остальные IANA/custom claims сохраняются в `additional`.

Это не компромисс, а важное свойство API: IANA JWT Claims Registry является
расширяемым и содержит claims из множества независимых спецификаций с
различными типами и семантикой.

Validation отделена от cryptographic verification:

```text
parse
  ↓
verify signature
  ↓
decode claims
  ↓
validate application policy
```

## IANA coverage

`src/registry.rs` содержит snapshot имён:

- JOSE Header Parameters;
- JWS Algorithms;
- JWE Key Management Algorithms;
- JWE Content Encryption Algorithms;
- JWT Claims;
- JWK Key Types, parameters, curves, uses и key operations;
- JWE Compression Algorithms.

Неизвестные будущие значения не уничтожаются парсером.

## Что намеренно ещё не подключено к crypto backend

Архитектура уже допускает расширение, но эта версия не притворяется, что
реализует алгоритм, если backend отсутствует.

Не подключены:

- `RSA1_5` crypto operation (идентификатор известен registry, baseline намеренно отключён);
- Ed448;
- ML-DSA-44 / ML-DSA-65 / ML-DSA-87;
- AES-KW;
- AES-GCM Key Wrap;
- ECDH-ES;
- PBES2;
- A128CBC-HS256 / A192CBC-HS384 / A256CBC-HS512;
- A192GCM.

Идентификаторы остаются известны registry, но crypto operation вернёт
`UnsupportedAlgorithm`.

## Почему `alg` хранится как String

JOSE registries расширяемы. Закрытый Rust `enum`, который обязан знать каждый
будущий алгоритм на момент компиляции, делает parser хрупким.

Внутренние crypto providers при этом всё равно используют точное значение
алгоритма и никогда не выбираются только по недоверенному `alg` из токена.

## Security model

Никогда не делайте:

```rust
verify(token, key)
```

без policy.

Правильная модель для JWS/JWT:

```rust
let policy = VerificationPolicy::new()
    .allow_algorithm("Ed25519");

jwt::verify(token, &key, &policy, &claims_validation)?;
```

И аналогично для JWE:

```rust
let policy = JweDecryptionPolicy::new()
    .allow_key_management("RSA-OAEP-256")
    .allow_content_encryption("A256GCM");
```

Алгоритм из токена является недоверенными данными. Он должен совпасть:

1. с allow-list caller-а;
2. с алгоритмом конкретного verifier;
3. с типом и параметрами ключа.

## Запуск

```bash
cargo test
cargo run --example hs256
```

## Следующие этапы

1. Довести JWS JSON Serialization до полноценного signing/verifying API.
2. Добавить импорт JWK → backend key types.
3. Добавить AES-KW.
4. Добавить ECDH-ES + Concat KDF.
5. Добавить CBC-HMAC content encryption.
6. Добавить PBES2.
7. Добавить Ed448.
8. Добавить ML-DSA.
9. Подключить официальный набор RFC 7520 interoperability vectors.
10. Добавить fuzzing парсеров и property tests.

## Статус проверки

Это продолжение семейства [JWT/LWT](https://github.com/topics/localzet-tokens). Исправлена ошибка комментария, мешавшая компиляции. `cargo test --locked --all-targets` проверен на Rust 1.98.1. Минимальная версия по требованиям зафиксированных зависимостей — Rust 1.85 (прежнее значение 1.75 не соответствовало lock-файлу). CI отдельно проверяет обе версии. В CI предупреждения Clippy для библиотеки считаются ошибками. Deprecated GenericArray вызовы устранены; добавлены проверки отказа для повреждённых AEAD-параметров и недоверенных JWS. Расширение interoperability/fuzz tests остаётся задачей до production-релиза.

[English documentation](README.md).

## Attribution

Maintainer of Localzet contributions: **Ivan Zorin (localzet)** — <creator@localzet.com> · https://www.localzet.com. Copyright © 2026 Localzet Group. Original authorship and third-party licenses remain applicable. See [AUTHORS](.github/AUTHORS.md).
