use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::claims::JwtClaims;
use crate::error::{JoseError, Result};

/**
 * Политика прикладной валидации JWT Claims.
 */
#[derive(Debug, Clone, Default)]
pub struct ClaimsValidation {
    now: Option<f64>,
    leeway_seconds: f64,
    expected_issuer: Option<String>,
    expected_audiences: BTreeSet<String>,
    require_expiration: bool,
    validate_issued_at: bool,
}

impl ClaimsValidation {
    pub fn new() -> Self {
        Self::default()
    }

    /**
     * Устанавливает фиксированное текущее время.
     *
     * Полезно для тестов и воспроизводимой проверки.
     */
    pub fn at_time(mut self, unix_seconds: f64) -> Self {
        self.now = Some(unix_seconds);
        self
    }

    /**
     * Устанавливает допустимое рассогласование часов.
     */
    pub fn leeway(mut self, seconds: f64) -> Self {
        self.leeway_seconds = seconds.max(0.0);
        self
    }

    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.expected_issuer = Some(issuer.into());
        self
    }

    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.expected_audiences.insert(audience.into());
        self
    }

    pub fn require_expiration(mut self, value: bool) -> Self {
        self.require_expiration = value;
        self
    }

    pub fn validate_issued_at(mut self, value: bool) -> Self {
        self.validate_issued_at = value;
        self
    }

    /**
     * Выполняет валидацию claims.
     */
    pub fn validate(&self, claims: &JwtClaims) -> Result<()> {
        let now = self.now.unwrap_or_else(system_time);

        if self.require_expiration && claims.exp.is_none() {
            return Err(JoseError::MissingClaim("exp"));
        }

        if let Some(exp) = &claims.exp {
            let exp = exp.as_f64().ok_or(JoseError::InvalidClaim("exp"))?;

            if now > exp + self.leeway_seconds {
                return Err(JoseError::Expired);
            }
        }

        if let Some(nbf) = &claims.nbf {
            let nbf = nbf.as_f64().ok_or(JoseError::InvalidClaim("nbf"))?;

            if now + self.leeway_seconds < nbf {
                return Err(JoseError::NotYetValid);
            }
        }

        if self.validate_issued_at {
            if let Some(iat) = &claims.iat {
                let iat = iat.as_f64().ok_or(JoseError::InvalidClaim("iat"))?;

                if iat > now + self.leeway_seconds {
                    return Err(JoseError::InvalidIssuedAt);
                }
            }
        }

        if let Some(expected) = &self.expected_issuer {
            if claims.iss.as_deref() != Some(expected.as_str()) {
                return Err(JoseError::IssuerMismatch);
            }
        }

        if !self.expected_audiences.is_empty() {
            let audience = claims.aud.as_ref().ok_or(JoseError::AudienceMismatch)?;

            if !self
                .expected_audiences
                .iter()
                .any(|expected| audience.contains(expected))
            {
                return Err(JoseError::AudienceMismatch);
            }
        }

        Ok(())
    }
}

fn system_time() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs_f64())
        .unwrap_or(0.0)
}
