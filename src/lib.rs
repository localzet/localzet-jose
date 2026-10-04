#![forbid(unsafe_code)]

/**
 * localzet-jose
 *
 * Библиотека разделена по сущностям семейства JOSE:
 *
 * - JWA — идентификаторы и криптографические алгоритмы;
 * - JWK — представление и наборы ключей;
 * - JWS — цифровая подпись и MAC;
 * - JWE — шифрование;
 * - JWT — Claims Set и прикладная валидация.
 *
 * Важно: синтаксический разбор, криптографическая проверка и прикладная
 * валидация являются разными этапами и не смешиваются в одну операцию.
 */

pub mod claims;
pub mod error;
pub mod header;
pub mod jwa;
pub mod jwk;
pub mod jwe;
pub mod jws;
pub mod registry;
pub mod jwt;
pub mod policy;

mod base64url;

pub use claims::{Audience, JwtClaims, NumericDate};
pub use error::{JoseError, Result};
pub use header::JoseHeader;
pub use policy::{JweDecryptionPolicy, VerificationPolicy};
