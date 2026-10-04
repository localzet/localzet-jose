use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/**
 * Одна подпись JWS JSON Serialization.
 */
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwsJsonSignature {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<Map<String, Value>>,

    pub signature: String,
}

/**
 * JWS General JSON Serialization.
 */
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwsGeneralJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,

    pub signatures: Vec<JwsJsonSignature>,
}

/**
 * JWS Flattened JSON Serialization.
 */
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwsFlattenedJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<Map<String, Value>>,

    pub signature: String,
}
