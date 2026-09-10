//! Pure helpers for the command line: input parsing, the device-screen
//! summary, and the typed confirmation. Kept free of I/O so they are testable.

use crate::error::{Error, Result};

/// Domain-separated challenge used by `address` to fetch the public key.
/// It can never equal SHA3-256 of a real block hash, so the resulting
/// signature is worthless and is discarded.
pub const PUBKEY_FETCH_DOMAIN: &[u8] = b"keeta-trezor pubkey fetch v1";

pub fn parse_block_hash(hex_str: &str) -> Result<[u8; 32]> {
    let s = hex_str.trim();
    if s.len() != 64 {
        return Err(Error::BadInput(format!(
            "block hash must be 64 hex characters, got {}",
            s.len()
        )));
    }
    let bytes =
        hex::decode(s).map_err(|e| Error::BadInput(format!("block hash is not hex: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| Error::BadInput("block hash must be 32 bytes".into()))
}

/// Shown on the Trezor screen next to the identity. ASCII, under 40 chars.
pub fn visual_summary(block_hash: &[u8; 32]) -> String {
    let h = hex::encode(block_hash);
    format!("KEETA {}..{}", &h[..8], &h[56..])
}

/// The user must type the last 6 hex chars of the hash before the device is called.
pub fn confirmation_matches(block_hash: &[u8; 32], typed: &str) -> bool {
    let h = hex::encode(block_hash);
    typed.trim().eq_ignore_ascii_case(&h[58..])
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn parses_64_hex_chars() {
        let h = parse_block_hash(H).unwrap();
        assert_eq!(h[0], 0x01);
        assert_eq!(h[31], 0xef);
    }

    #[test]
    fn accepts_uppercase_and_surrounding_whitespace() {
        assert!(parse_block_hash(&format!("  {}\n", H.to_uppercase())).is_ok());
    }

    #[test]
    fn rejects_wrong_length_and_non_hex() {
        assert!(matches!(
            parse_block_hash(&H[..62]),
            Err(Error::BadInput(_))
        ));
        assert!(matches!(
            parse_block_hash(&format!("{H}00")),
            Err(Error::BadInput(_))
        ));
        assert!(matches!(
            parse_block_hash(&H.replace('a', "g")),
            Err(Error::BadInput(_))
        ));
        assert!(matches!(parse_block_hash(""), Err(Error::BadInput(_))));
    }

    #[test]
    fn visual_summary_is_short_ascii() {
        let s = visual_summary(&parse_block_hash(H).unwrap());
        assert_eq!(s, "KEETA 01234567..89abcdef");
        assert!(s.is_ascii());
        assert!(s.len() <= 40);
    }

    #[test]
    fn confirmation_checks_last_six_hex_chars() {
        let h = parse_block_hash(H).unwrap();
        assert!(confirmation_matches(&h, "abcdef"));
        assert!(confirmation_matches(&h, " ABCDEF\n"));
        assert!(!confirmation_matches(&h, "abcde"));
        assert!(!confirmation_matches(&h, "123456"));
    }
}
