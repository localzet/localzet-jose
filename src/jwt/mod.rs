mod validation;

use crate::claims::JwtClaims;
use crate::error::Result;
use crate::header::JoseHeader;
use crate::jwa::{JwsSigner, JwsVerifier};
use crate::jws::{sign_compact, verify_compact};
use crate::policy::VerificationPolicy;

pub use validation::ClaimsValidation;

/**
 * Создаёт signed JWT в JWS Compact Serialization.
 */
pub fn sign(header: &JoseHeader, claims: &JwtClaims, signer: &dyn JwsSigner) -> Result<String> {
    let payload = serde_json::to_vec(claims)?;
    sign_compact(header, &payload, signer)
}

/**
 * Проверяет signed JWT и выполняет прикладную валидацию claims.
 */
pub fn verify(
    token: &str,
    verifier: &dyn JwsVerifier,
    verification_policy: &VerificationPolicy,
    claims_validation: &ClaimsValidation,
) -> Result<(JoseHeader, JwtClaims)> {
    let verified = verify_compact(token, None, verifier, verification_policy)?;
    let claims: JwtClaims = serde_json::from_slice(&verified.payload)?;

    claims_validation.validate(&claims)?;

    Ok((verified.header, claims))
}
