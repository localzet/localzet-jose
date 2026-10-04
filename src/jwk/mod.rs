use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::base64url;
use crate::error::{JoseError, Result};

/**
 * JSON Web Key.
 *
 * Common JWK parameters представлены явно, а параметры конкретного kty
 * (n/e/d, crv/x/y, k и т.д.) сохраняются в params. Такой подход не ломает
 * парсер при появлении новых Key Types и параметров в IANA registry.
 */
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,

    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_ops: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub x5c: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,

    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,

    #[serde(flatten)]
    pub params: Map<String, Value>,
}

impl Jwk {
    /**
     * Возвращает симметричный ключ kty=oct.
     */
    pub fn octet_key(&self) -> Result<Vec<u8>> {
        if self.kty != "oct" {
            return Err(JoseError::InvalidKey);
        }

        let encoded = self
            .params
            .get("k")
            .and_then(Value::as_str)
            .ok_or(JoseError::InvalidKey)?;

        base64url::decode(encoded)
    }

    /**
     * Вычисляет JWK SHA-256 Thumbprint согласно RFC 7638.
     *
     * В thumbprint входят только обязательные публичные параметры kty.
     */
    pub fn thumbprint_sha256(&self) -> Result<String> {
        let canonical = match self.kty.as_str() {
            "RSA" => {
                let e = required_string(&self.params, "e")?;
                let n = required_string(&self.params, "n")?;
                format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#)
            }
            "EC" => {
                let crv = required_string(&self.params, "crv")?;
                let x = required_string(&self.params, "x")?;
                let y = required_string(&self.params, "y")?;
                format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#)
            }
            "OKP" => {
                let crv = required_string(&self.params, "crv")?;
                let x = required_string(&self.params, "x")?;
                format!(r#"{{"crv":"{crv}","kty":"OKP","x":"{x}"}}"#)
            }
            // AKP определён отдельной современной спецификацией и имеет
            // другой набор обязательных параметров. Не применяем к нему
            // правила thumbprint для OKP автоматически.
            "AKP" => return Err(JoseError::UnsupportedAlgorithm("AKP thumbprint".to_owned())),
            "oct" => {
                let k = required_string(&self.params, "k")?;
                format!(r#"{{"k":"{k}","kty":"oct"}}"#)
            }
            _ => return Err(JoseError::InvalidKey),
        };

        Ok(base64url::encode(&Sha256::digest(canonical.as_bytes())))
    }
}

fn required_string<'a>(map: &'a Map<String, Value>, name: &str) -> Result<&'a str> {
    map.get(name)
        .and_then(Value::as_str)
        .ok_or(JoseError::InvalidKey)
}

/**
 * JSON Web Key Set.
 */
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,

    #[serde(flatten)]
    pub additional: Map<String, Value>,
}

impl JwkSet {
    /**
     * Возвращает все ключи с указанным kid.
     *
     * kid не обязан быть глобально уникальным, поэтому API возвращает iterator.
     */
    pub fn by_kid<'a>(&'a self, kid: &'a str) -> impl Iterator<Item = &'a Jwk> + 'a {
        self.keys
            .iter()
            .filter(move |key| key.kid.as_deref() == Some(kid))
    }
}
