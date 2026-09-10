//! Keeta address encoding and signature verification, via the official SDK
//! crates so the tool cannot drift from what the network accepts.

use crate::error::{Error, Result};
use keetanetwork_account::{
    Account, AccountPublicKey, Accountable, KeyECDSASECP256R1, KeyPairType, Keyable,
};
use sha3::{Digest, Sha3_256};

fn account_from_pubkey(pubkey: &[u8; 33]) -> Result<Account<KeyECDSASECP256R1>> {
    Account::<KeyECDSASECP256R1>::try_from(Accountable::KeyAndType(
        Keyable::PublicKey(pubkey.to_vec()),
        KeyPairType::ECDSASECP256R1,
    ))
    .map_err(|e| Error::Keeta(e.to_string()))
}

/// `keeta_…` address for a compressed P-256 public key (key type 6).
pub fn address_from_pubkey(pubkey: &[u8; 33]) -> Result<String> {
    account_from_pubkey(pubkey)?
        .to_public_key_string()
        .map_err(|e| Error::Keeta(e.to_string()))
}

/// Parse a `keeta_…` address; must be a P-256 (key type 6) address with a valid checksum.
pub fn pubkey_from_address(address: &str) -> Result<[u8; 33]> {
    let account: Account<KeyECDSASECP256R1> =
        address
            .parse()
            .map_err(|e: keetanetwork_account::AccountError| {
                Error::BadInput(format!("{address}: not a valid P-256 keeta address ({e})"))
            })?;
    account
        .as_public_key_bytes()
        .try_into()
        .map_err(|_| Error::BadInput(format!("{address}: public key is not 33 bytes")))
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    Sha3_256::digest(data).into()
}

/// Verify exactly the way the network does: the SDK hashes `block_hash` with
/// SHA3-256 and verifies the raw r‖s signature against the P-256 key.
pub fn verify_block_signature(
    pubkey: &[u8; 33],
    block_hash: &[u8; 32],
    signature: &[u8; 64],
) -> Result<()> {
    account_from_pubkey(pubkey)?
        .verify(block_hash, signature, None)
        .map_err(|e| Error::VerifyFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Handoff 11.1: verified by the Python script and the Keeta JS SDK.
    const PUBKEY_HEX: &str = "034aa10c8fac44899628ccc132eb7162f63c912e7bf372bbb1dc8a69910ee2638c";
    const ADDRESS: &str = "keeta_aybuviimr6wejcmwfdgmcmxlofrpmperfz57g4v3whoiu2mrb3rghdc2med7ibi";

    fn pubkey() -> [u8; 33] {
        hex::decode(PUBKEY_HEX).unwrap().try_into().unwrap()
    }

    #[test]
    fn address_vector_encodes() {
        assert_eq!(address_from_pubkey(&pubkey()).unwrap(), ADDRESS);
    }

    #[test]
    fn address_vector_decodes() {
        assert_eq!(pubkey_from_address(ADDRESS).unwrap(), pubkey());
    }

    #[test]
    fn address_with_bad_checksum_is_rejected() {
        let mut bad = ADDRESS.to_string();
        let mid = 30;
        let c = bad.as_bytes()[mid] as char;
        let replacement = if c == 'a' { 'b' } else { 'a' };
        bad.replace_range(mid..mid + 1, &replacement.to_string());
        assert!(pubkey_from_address(&bad).is_err());
    }

    #[test]
    fn non_canonical_last_char_decodes_to_same_key_and_recanonicalizes() {
        // The last base32 character carries 3 unused bits, so `…ibi` and `…ibj`
        // decode to the same key. The canonical spelling comes from re-encoding.
        let mut alt = ADDRESS.to_string();
        alt.replace_range(alt.len() - 1.., "j");
        assert_ne!(alt, ADDRESS);
        assert_eq!(pubkey_from_address(&alt).unwrap(), pubkey());
        assert_eq!(
            address_from_pubkey(&pubkey_from_address(&alt).unwrap()).unwrap(),
            ADDRESS
        );
    }

    #[test]
    fn non_p256_address_is_rejected() {
        // Key type byte 0 (secp256k1), not the P-256 type (6) we sign with.
        let ed = "keeta_aabt3sbgkku2cipye2h6ill2kdi6a7tsanpoe4a3xpvtyuwefowvaklvvxvr74a";
        assert!(pubkey_from_address(ed).is_err());
    }

    /// Handoff M2 "digest proof": pins down that the device must sign
    /// SHA3-256(block_hash), not block_hash. Uses an SDK P-256 account from a
    /// fixed TEST seed; no user key material is involved.
    #[test]
    fn digest_proof_sdk_signature_is_over_sha3_of_hash() {
        use keetanetwork_account::{Account, AccountPublicKey, KeyECDSASECP256R1};
        use keetanetwork_crypto::algorithms::secp256r1::Secp256r1Derivation;
        use keetanetwork_crypto::prelude::{IntoSecret, KeyDerivation};
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        use p256::ecdsa::{Signature, VerifyingKey};

        let seed: [u8; 32] = [7u8; 32];
        let private_key = Secp256r1Derivation::derive_from_seed(seed.into_secret()).unwrap();
        let account = Account::<KeyECDSASECP256R1>::from(private_key);
        let pubkey: [u8; 33] = account.as_public_key_bytes().try_into().unwrap();

        let block_hash: [u8; 32] = sha3_256(b"some block bytes");
        let sig_bytes: [u8; 64] = account.sign(block_hash, None).unwrap().try_into().unwrap();

        let vk = VerifyingKey::from_sec1_bytes(&pubkey).unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        // Correct digest: SHA3-256(block_hash)
        assert!(vk.verify_prehash(&sha3_256(&block_hash), &sig).is_ok());
        // Wrong digest: the raw block hash
        assert!(vk.verify_prehash(&block_hash, &sig).is_err());
        // Our helper agrees with the SDK.
        assert!(verify_block_signature(&pubkey, &block_hash, &sig_bytes).is_ok());
        // And rejects a tampered signature.
        let mut tampered = sig_bytes;
        tampered[10] ^= 1;
        assert!(verify_block_signature(&pubkey, &block_hash, &tampered).is_err());
    }
}
