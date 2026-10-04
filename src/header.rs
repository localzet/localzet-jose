use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::claims::Audience;
use crate::error::{JoseError, Result};

/**
 * JOSE Header.
 *
 * Все Header Parameters, зарегистрированные в IANA JOSE Registry на момент
 * создания этой версии библиотеки, имеют явные поля там, где их тип стабилен.
 * Параметры расширений со сложной или профильно-зависимой структурой хранятся
 * как serde_json::Value.
 *
 * Неизвестные будущие параметры сохраняются в additional.
 */
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct JoseHeader {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Value>,

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

    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub crit: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub enc: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub epk: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub apu: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub apv: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub p2s: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub p2c: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Audience>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub b64: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppt: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub svt: Option<String>,

    #[serde(rename = "iheSSId", skip_serializing_if = "Option::is_none")]
    pub ihe_ss_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_chain: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_trust_chain: Option<Value>,

    #[serde(flatten)]
    pub additional: Map<String, Value>,
}

impl JoseHeader {
    /**
     * Возвращает значение alg.
     */
    pub fn algorithm(&self) -> Result<&str> {
        self.alg
            .as_deref()
            .ok_or(JoseError::MissingHeaderParameter("alg"))
    }

    /**
     * Возвращает значение enc.
     */
    pub fn encryption_algorithm(&self) -> Result<&str> {
        self.enc
            .as_deref()
            .ok_or(JoseError::MissingHeaderParameter("enc"))
    }

    /**
     * Возвращает режим кодирования JWS Payload.
     *
     * Отсутствующее b64 эквивалентно true согласно RFC 7797.
     */
    pub fn payload_is_base64url_encoded(&self) -> bool {
        self.b64.unwrap_or(true)
    }

    /**
     * Проверяет корректность Critical Header Parameters.
     *
     * understood содержит расширения, которые вызывающая сторона действительно
     * умеет обработать. Зарегистрированность параметра сама по себе не означает,
     * что приложение понимает его семантику.
     */
    pub fn validate_critical(&self, understood: &[String]) -> Result<()> {
        if self.crit.iter().any(|name| name.is_empty()) {
            return Err(JoseError::InvalidCriticalHeader);
        }

        for name in &self.crit {
            if !understood.iter().any(|value| value == name) {
                return Err(JoseError::UnsupportedCriticalHeader(name.clone()));
            }

            if !self.contains_parameter(name) {
                return Err(JoseError::InvalidCriticalHeader);
            }
        }

        if self.b64 == Some(false) && !self.crit.iter().any(|value| value == "b64") {
            return Err(JoseError::MissingB64Critical);
        }

        Ok(())
    }

    /**
     * Проверяет наличие Header Parameter по его wire-name.
     */
    pub fn contains_parameter(&self, name: &str) -> bool {
        match name {
            "alg" => self.alg.is_some(),
            "jku" => self.jku.is_some(),
            "jwk" => self.jwk.is_some(),
            "kid" => self.kid.is_some(),
            "x5u" => self.x5u.is_some(),
            "x5c" => !self.x5c.is_empty(),
            "x5t" => self.x5t.is_some(),
            "x5t#S256" => self.x5t_s256.is_some(),
            "typ" => self.typ.is_some(),
            "cty" => self.cty.is_some(),
            "crit" => !self.crit.is_empty(),
            "enc" => self.enc.is_some(),
            "zip" => self.zip.is_some(),
            "epk" => self.epk.is_some(),
            "apu" => self.apu.is_some(),
            "apv" => self.apv.is_some(),
            "iv" => self.iv.is_some(),
            "tag" => self.tag.is_some(),
            "p2s" => self.p2s.is_some(),
            "p2c" => self.p2c.is_some(),
            "iss" => self.iss.is_some(),
            "sub" => self.sub.is_some(),
            "aud" => self.aud.is_some(),
            "b64" => self.b64.is_some(),
            "ppt" => self.ppt.is_some(),
            "url" => self.url.is_some(),
            "nonce" => self.nonce.is_some(),
            "svt" => self.svt.is_some(),
            "iheSSId" => self.ihe_ss_id.is_some(),
            "jwt" => self.jwt.is_some(),
            "client_id" => self.client_id.is_some(),
            "trust_chain" => self.trust_chain.is_some(),
            "peer_trust_chain" => self.peer_trust_chain.is_some(),
            other => self.additional.contains_key(other),
        }
    }
}
