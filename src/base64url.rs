use base64ct::{Base64UrlUnpadded, Encoding};

use crate::error::{JoseError, Result};

/**
 * Кодирует последовательность байтов в Base64URL без padding.
 */
pub(crate) fn encode(input: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(input)
}

/**
 * Декодирует Base64URL без padding.
 */
pub(crate) fn decode(input: &str) -> Result<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(input).map_err(|_| JoseError::Base64)
}
