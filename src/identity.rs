#![allow(dead_code)] // used by main in a later task

//! SLIP-0013 identity → derivation path, as computed by Trezor firmware
//! (`core/src/apps/misc/sign_identity.py::get_identity_path`).
//! Display only: the device derives the key itself. This lets the user record
//! and cross-check the path against the Python recovery script.

use sha2::{Digest, Sha256};

pub struct Identity {
    pub user: String,
    pub host: String,
    pub index: u32,
}

impl Identity {
    pub const PROTO: &'static str = "gpg";
    pub const CURVE: &'static str = "nist256p1";

    /// Full identity string hashed into the path: `gpg://user@host`.
    pub fn identity_string(&self) -> String {
        format!("{}://{}@{}", Self::PROTO, self.user, self.host)
    }

    /// What the Safe 3 shows on screen (identity without the protocol).
    pub fn display_string(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }

    /// `m/13'/A'/B'/C'/D'` components without the hardened bit.
    pub fn path(&self) -> [u32; 5] {
        let mut hasher = Sha256::new();
        hasher.update(self.index.to_le_bytes());
        hasher.update(self.identity_string().as_bytes());
        let h = hasher.finalize();
        let word =
            |i: usize| u32::from_le_bytes([h[i], h[i + 1], h[i + 2], h[i + 3]]) & 0x7fff_ffff;
        [13, word(0), word(4), word(8), word(12)]
    }

    pub fn path_string(&self) -> String {
        let p = self.path();
        format!("m/{}'/{}'/{}'/{}'/{}'", p[0], p[1], p[2], p[3], p[4])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(user: &str, host: &str, index: u32) -> Identity {
        Identity {
            user: user.into(),
            host: host.into(),
            index,
        }
    }

    #[test]
    fn identity_string_has_gpg_prefix() {
        assert_eq!(
            id("keeta-cold", "vault", 0).identity_string(),
            "gpg://keeta-cold@vault"
        );
        assert_eq!(
            id("keeta-cold", "vault", 0).display_string(),
            "keeta-cold@vault"
        );
    }

    #[test]
    fn path_vector_vault_index_0() {
        assert_eq!(
            id("keeta-cold", "vault", 0).path_string(),
            "m/13'/1475921902'/1170799771'/165906238'/1390816825'"
        );
    }

    #[test]
    fn path_vector_local_index_0() {
        assert_eq!(
            id("keeta-cold", "local", 0).path_string(),
            "m/13'/1300177738'/1772559091'/849607749'/942002604'"
        );
    }

    #[test]
    fn path_vector_local_index_1() {
        assert_eq!(
            id("keeta-cold", "local", 1).path_string(),
            "m/13'/1060405250'/1211320303'/1886099059'/1452342816'"
        );
    }

    #[test]
    fn default_identity_path() {
        // gpg://keeta@keeta index 0, computed with the Python recovery script logic.
        assert_eq!(
            id("keeta", "keeta", 0).path_string(),
            "m/13'/1196629790'/1629302093'/1078823676'/490899098'"
        );
    }

    #[test]
    fn index_changes_path() {
        assert_ne!(
            id("keeta-cold", "vault", 0).path(),
            id("keeta-cold", "vault", 1).path()
        );
    }
}
