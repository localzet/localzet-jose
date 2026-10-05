#![forbid(unsafe_code)]
// SPDX-FileCopyrightText: 2026 Ivan Zorin <creator@localzet.com> (Localzet contributions)
// SPDX-License-Identifier: AGPL-3.0

//! JOSE models, cryptographic framing and explicit application policies.
//! Parsing, signature verification and claim validation are separate stages.

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
