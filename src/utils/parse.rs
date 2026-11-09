/*
 * Copyright (C) 2026 - Universidad Politécnica de Madrid - UPM
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use crate::errors::{Errors, Outcome};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub fn hex_decode(decode: &str) -> Outcome<Vec<u8>> {
    hex::decode(decode).map_err(|e| Errors::parse("invalid signing_key_hex", Some(Box::new(e))))
}

// ===== BASE64URL REWIRING ENGINE =================================================================

/// Decodes an unpadded, URL-safe Base64 encoded payload back into raw vector bytes.
pub fn decode_url_safe_no_pad(data: &str) -> Outcome<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(data).map_err(|e| {
        Errors::parse(
            format!("Unable to decode url safe no pad: {}", data),
            Some(Box::new(e)),
        )
    })
}

/// Encodes an arbitrary byte matrix array slice into an unpadded, URL-safe Base64 string literal.
pub fn encode_url_safe_no_pad(data: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(data)
}
