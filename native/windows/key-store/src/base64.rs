use crate::zeroize::{ZeroizingBase64, ZeroizingKey};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes an exact 32-byte key to canonical 44-character RFC 4648 standard base64
/// ending in a single `=` padding character.
pub fn encode_key_base64(key: &ZeroizingKey) -> ZeroizingBase64 {
    let src = key.as_bytes();
    let mut out = [0u8; 44];
    let mut j = 0usize;

    for i in (0..30).step_by(3) {
        let b0 = src[i];
        let b1 = src[i + 1];
        let b2 = src[i + 2];
        out[j] = ALPHABET[(b0 >> 2) as usize];
        out[j + 1] = ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize];
        out[j + 2] = ALPHABET[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize];
        out[j + 3] = ALPHABET[(b2 & 0x3F) as usize];
        j += 4;
    }

    let b0 = src[30];
    let b1 = src[31];
    out[40] = ALPHABET[(b0 >> 2) as usize];
    out[41] = ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize];
    out[42] = ALPHABET[((b1 & 0x0F) << 2) as usize];
    out[43] = b'=';

    ZeroizingBase64::new(out)
}

/// Decodes a canonical 44-character RFC 4648 base64 string into a 32-byte key.
pub fn decode_key_base64(encoded: &str) -> Option<ZeroizingKey> {
    let bytes = encoded.as_bytes();
    if bytes.len() != 44 || bytes[43] != b'=' {
        return None;
    }

    let mut key = ZeroizingKey::zeroed();
    let dst = key.as_bytes_mut();
    let mut out_idx = 0usize;

    for i in (0..40).step_by(4) {
        let v0 = decode_sextet(bytes[i])?;
        let v1 = decode_sextet(bytes[i + 1])?;
        let v2 = decode_sextet(bytes[i + 2])?;
        let v3 = decode_sextet(bytes[i + 3])?;
        dst[out_idx] = (v0 << 2) | (v1 >> 4);
        dst[out_idx + 1] = (v1 << 4) | (v2 >> 2);
        dst[out_idx + 2] = (v2 << 6) | v3;
        out_idx += 3;
    }

    let v0 = decode_sextet(bytes[40])?;
    let v1 = decode_sextet(bytes[41])?;
    let v2 = decode_sextet(bytes[42])?;
    // Enforce canonical zero padding bits in the final base64 character.
    if (v2 & 0x03) != 0 {
        return None;
    }
    dst[30] = (v0 << 2) | (v1 >> 4);
    dst[31] = (v1 << 4) | (v2 >> 2);

    Some(key)
}

fn decode_sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_known_vectors() {
        let zero_key = ZeroizingKey::zeroed();
        let encoded = encode_key_base64(&zero_key);
        assert_eq!(encoded.as_str(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        let decoded = decode_key_base64(encoded.as_str()).expect("valid base64");
        assert_eq!(decoded.as_bytes(), zero_key.as_bytes());

        let mut seq = [0u8; 32];
        for (i, slot) in seq.iter_mut().enumerate() {
            *slot = i as u8;
        }
        let seq_key = ZeroizingKey::from_slice(&seq).unwrap();
        let seq_b64 = encode_key_base64(&seq_key);
        assert_eq!(seq_b64.as_str(), "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=");
        let decoded_seq = decode_key_base64(seq_b64.as_str()).expect("valid base64");
        assert_eq!(decoded_seq.as_bytes(), &seq);
    }

    #[test]
    fn rejects_non_canonical_and_malformed_base64() {
        // Non-zero padding bits in character index 42 ('B' instead of 'A')
        assert!(decode_key_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=").is_none());
        // Wrong length
        assert!(decode_key_base64("AAAA").is_none());
        // Missing '='
        assert!(decode_key_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_none());
        // Invalid character
        assert!(decode_key_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA_=").is_none());
    }
}
