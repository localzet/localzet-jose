use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/**
 * Получатель JWE General JSON Serialization.
 */
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JweJsonRecipient {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<Map<String, Value>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_key: Option<String>,
}

/**
 * JWE General JSON Serialization.
 */
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JweGeneralJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub unprotected: Option<Map<String, Value>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,

    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
    pub recipients: Vec<JweJsonRecipient>,
}

/**
 * JWE Flattened JSON Serialization.
 */
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JweFlattenedJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub unprotected: Option<Map<String, Value>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<Map<String, Value>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,

    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
}
