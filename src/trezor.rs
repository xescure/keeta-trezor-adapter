//! Trezor `SignIdentity` (SLIP-0013) with `proto = gpg`, `curve = nist256p1`.
//! With `gpg` the device signs `challenge_hidden` unmodified (verified in
//! firmware `core/src/apps/misc/sign_identity.py`), so we pass the exact
//! 32-byte digest Keeta expects. The reply signature is `0x00 || r || s`.

// wired in by main in a later task; sign_identity and its Reply fields are
// unused until then.
#![allow(dead_code)]

use crate::error::{Error, Result};
use crate::identity::Identity;
use trezor_client::client::handle_interaction;
use trezor_client::protos;

pub struct Reply {
    pub pubkey: [u8; 33],
    pub signature: [u8; 64],
}

/// Validate the raw reply fields. Pure so it can be tested without a device.
pub fn parse_reply(public_key: &[u8], signature: &[u8]) -> Result<Reply> {
    let pubkey: [u8; 33] = public_key.try_into().map_err(|_| {
        Error::Device(format!(
            "public key is {} bytes, expected 33",
            public_key.len()
        ))
    })?;
    if pubkey[0] != 0x02 && pubkey[0] != 0x03 {
        return Err(Error::Device(format!(
            "public key prefix 0x{:02x} is not a compressed point",
            pubkey[0]
        )));
    }
    if signature.len() != 65 {
        return Err(Error::MalformedSignature(format!(
            "{} bytes, expected 65",
            signature.len()
        )));
    }
    if signature[0] != 0x00 {
        return Err(Error::MalformedSignature(format!(
            "first byte 0x{:02x}, expected 0x00",
            signature[0]
        )));
    }
    let sig: [u8; 64] = signature[1..].try_into().expect("checked length");
    Ok(Reply {
        pubkey,
        signature: sig,
    })
}

fn build_request(
    identity: &Identity,
    challenge_hidden: [u8; 32],
    challenge_visual: &str,
) -> protos::SignIdentity {
    let mut id = protos::IdentityType::new();
    id.set_proto(Identity::PROTO.to_string());
    id.set_user(identity.user.clone());
    id.set_host(identity.host.clone());
    id.set_index(identity.index);

    let mut req = protos::SignIdentity::new();
    req.identity = Some(id).into();
    req.set_challenge_hidden(challenge_hidden.to_vec());
    req.set_challenge_visual(challenge_visual.to_string());
    req.set_ecdsa_curve_name(Identity::CURVE.to_string());
    req
}

/// Connect to the single attached Trezor (USB or emulator on UDP 21324),
/// send the request, drive button/passphrase prompts, and parse the reply.
/// Blocking: waits for the user to confirm on the device.
// wired in by main in a later task
pub fn sign_identity(
    identity: &Identity,
    challenge_hidden: [u8; 32],
    challenge_visual: &str,
) -> Result<Reply> {
    let dev = |e: trezor_client::Error| Error::Device(e.to_string());
    let mut trezor = trezor_client::unique(false).map_err(dev)?;
    trezor.init_device(None).map_err(dev)?;
    let req = build_request(identity, challenge_hidden, challenge_visual);
    let resp = trezor
        .call(req, Box::new(|_, m: protos::SignedIdentity| Ok(m)))
        .map_err(dev)?;
    let signed = handle_interaction(resp).map_err(dev)?;
    parse_reply(signed.public_key(), signed.signature())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk() -> Vec<u8> {
        let mut v = vec![0x03u8];
        v.extend_from_slice(&[0xabu8; 32]);
        v
    }

    fn sig65() -> Vec<u8> {
        let mut v = vec![0x00u8];
        v.extend_from_slice(&[0x11u8; 64]);
        v
    }

    #[test]
    fn accepts_65_byte_signature_with_zero_prefix() {
        let r = parse_reply(&pk(), &sig65()).unwrap();
        assert_eq!(r.pubkey[0], 0x03);
        assert_eq!(r.signature, [0x11u8; 64]);
    }

    #[test]
    fn rejects_signature_with_nonzero_prefix() {
        let mut s = sig65();
        s[0] = 0x1b;
        assert!(matches!(
            parse_reply(&pk(), &s),
            Err(Error::MalformedSignature(_))
        ));
    }

    #[test]
    fn rejects_64_byte_signature() {
        assert!(matches!(
            parse_reply(&pk(), &[0x11u8; 64]),
            Err(Error::MalformedSignature(_))
        ));
    }

    #[test]
    fn rejects_66_byte_signature() {
        let mut s = sig65();
        s.push(0);
        assert!(matches!(
            parse_reply(&pk(), &s),
            Err(Error::MalformedSignature(_))
        ));
    }

    #[test]
    fn rejects_uncompressed_or_short_pubkey() {
        assert!(parse_reply(&[0x04u8; 65], &sig65()).is_err());
        assert!(parse_reply(&[0x02u8; 32], &sig65()).is_err());
        assert!(parse_reply(&[0x05u8; 33], &sig65()).is_err());
    }
}
