#!/usr/bin/env python3
"""
Offline derivation of a Keeta address for a Trezor SignIdentity (SLIP-0013) key.

  BIP-39 mnemonic (+ passphrase) -> seed
  seed -> SLIP-0010 (nist256p1) at the SLIP-0013 path for the identity
  compressed public key -> Keeta address (keeta_...)

WARNING: mnemonic mode handles your master seed. Run it only on an offline
machine, and only for the recovery drill / break-glass recovery.
Normal use: take the public key the Trezor returns and use --pubkey instead.

Supports BIP-39 backups only (not SLIP-39 / Shamir "Single-share" or multi-share).
This script is deliberately independent of the Rust tool (different language,
different libraries) so the two cross-check each other.
"""
import argparse, base64, hashlib, hmac, struct, sys, unicodedata, getpass
from ecdsa import NIST256p, SigningKey

CURVE_ORDER = NIST256p.order
HARDENED = 0x80000000
KEETA_KEYTYPE_SECP256R1 = 6

# ---------- BIP-39 ----------
def bip39_seed(mnemonic: str, passphrase: str) -> bytes:
    m = unicodedata.normalize("NFKD", " ".join(mnemonic.split()))
    s = unicodedata.normalize("NFKD", "mnemonic" + passphrase)
    return hashlib.pbkdf2_hmac("sha512", m.encode(), s.encode(), 2048)

# ---------- SLIP-0010 for nist256p1 ----------
def _pub(priv: bytes) -> bytes:
    return SigningKey.from_string(priv, curve=NIST256p).get_verifying_key().to_string("compressed")

def slip10_master(seed: bytes):
    I = hmac.new(b"Nist256p1 seed", seed, hashlib.sha512).digest()
    while True:
        k = int.from_bytes(I[:32], "big")
        if 0 < k < CURVE_ORDER:
            return I[:32], I[32:]
        I = hmac.new(b"Nist256p1 seed", I, hashlib.sha512).digest()

def slip10_child(priv: bytes, chain: bytes, index: int):
    if index & HARDENED:
        data = b"\x00" + priv + struct.pack(">I", index)
    else:
        data = _pub(priv) + struct.pack(">I", index)
    while True:
        I = hmac.new(chain, data, hashlib.sha512).digest()
        il = int.from_bytes(I[:32], "big")
        child = (il + int.from_bytes(priv, "big")) % CURVE_ORDER
        if il < CURVE_ORDER and child != 0:
            return child.to_bytes(32, "big"), I[32:]
        data = b"\x01" + I[32:] + struct.pack(">I", index)

def slip10_derive(seed: bytes, path):
    priv, chain = slip10_master(seed)
    for i in path:
        priv, chain = slip10_child(priv, chain, i)
    return priv

# ---------- SLIP-0013 identity path (matches Trezor firmware get_identity_path) ----------
def identity_path(identity: str, index: int = 0):
    h = hashlib.sha256(struct.pack("<I", index) + identity.encode()).digest()
    return [HARDENED | x for x in (13,) + struct.unpack("<IIII", h[:16])]

# ---------- Keeta address (matches SDK derivePublicKeyStringFromPublicKey) ----------
def keeta_address(pubkey: bytes, keytype: int = KEETA_KEYTYPE_SECP256R1) -> str:
    body = bytes([keytype]) + pubkey
    checksum = hashlib.sha3_256(body).digest()[:5]
    return "keeta_" + base64.b32encode(body + checksum).decode().rstrip("=").lower()

def fmt_path(p):
    return "m/" + "/".join(f"{x & ~HARDENED}'" if x & HARDENED else str(x) for x in p)

# ---------- self-test vectors ----------
def self_test() -> int:
    failures = 0
    def check(name, got, want):
        nonlocal failures
        ok = got == want
        failures += 0 if ok else 1
        print(f"{'ok  ' if ok else 'FAIL'} {name}")
        if not ok:
            print(f"     got  {got}\n     want {want}")

    # SLIP-0010 nist256p1 test vector 1 (satoshilabs/slips slip-0010.md)
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    vectors = [
        ([], "0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8"),
        ([HARDENED | 0], "0384610f5ecffe8fda089363a41f56a5c7ffc1d81b59a612d0d649b2d22355590c"),
        ([HARDENED | 0, 1], "03526c63f8d0b4bbbf9c80df553fe66742df4676b241dabefdef67733e070f6844"),
        ([HARDENED | 0, 1, HARDENED | 2], "0359cf160040778a4b14c5f4d7b76e327ccc8c4a6086dd9451b7482b5a4972dda0"),
        ([HARDENED | 0, 1, HARDENED | 2, 2, 1000000000], "02216cd26d31147f72427a453c443ed2cde8a1e53c9cc44e5ddf739725413fe3f4"),
    ]
    for path, want in vectors:
        check(f"slip10 {fmt_path(path)}", _pub(slip10_derive(seed, path)).hex(), want)

    # BIP-39 sanity vector
    mn = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    check("bip39 TREZOR passphrase", bip39_seed(mn, "TREZOR").hex()[:32], "c55257c360c07c72029aebc1b53c05ed")

    # SLIP-0013 path vectors (handoff 11.1)
    check("path gpg://keeta-cold@vault 0", fmt_path(identity_path("gpg://keeta-cold@vault", 0)),
          "m/13'/1475921902'/1170799771'/165906238'/1390816825'")
    check("path gpg://keeta-cold@local 0", fmt_path(identity_path("gpg://keeta-cold@local", 0)),
          "m/13'/1300177738'/1772559091'/849607749'/942002604'")
    check("path gpg://keeta-cold@local 1", fmt_path(identity_path("gpg://keeta-cold@local", 1)),
          "m/13'/1060405250'/1211320303'/1886099059'/1452342816'")
    check("path gpg://keeta-cold@vault 1", fmt_path(identity_path("gpg://keeta-cold@vault", 1)),
          "m/13'/3651116'/98985603'/1318097991'/1014682335'")

    # End-to-end chain vector (handoff 11.1, confirmed by the Keeta JS SDK)
    pub = _pub(slip10_derive(bip39_seed(mn, ""), identity_path("gpg://keeta-cold@vault", 0)))
    check("chain pubkey", pub.hex(), "034aa10c8fac44899628ccc132eb7162f63c912e7bf372bbb1dc8a69910ee2638c")
    check("chain address", keeta_address(pub), "keeta_aybuviimr6wejcmwfdgmcmxlofrpmperfz57g4v3whoiu2mrb3rghdc2med7ibi")

    print("all vectors passed" if failures == 0 else f"{failures} vector(s) FAILED")
    return 0 if failures == 0 else 1

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--identity", default="gpg://keeta@keeta",
                    help="exact SignIdentity string, e.g. gpg://user@host")
    ap.add_argument("--index", type=int, default=0)
    ap.add_argument("--pubkey", help="33-byte compressed P-256 key in hex (from the Trezor); skips the seed")
    ap.add_argument("--self-test", action="store_true", help="run the built-in test vectors and exit")
    a = ap.parse_args()

    if a.self_test:
        sys.exit(self_test())

    path = identity_path(a.identity, a.index)
    print("identity:", a.identity, "index:", a.index)
    print("path:    ", fmt_path(path))

    if a.pubkey:
        pub = bytes.fromhex(a.pubkey)
    else:
        mnemonic = getpass.getpass("BIP-39 mnemonic (hidden): ")
        passphrase = getpass.getpass("passphrase (empty if none): ")
        pub = _pub(slip10_derive(bip39_seed(mnemonic, passphrase), path))
    if len(pub) != 33 or pub[0] not in (2, 3):
        sys.exit("expected a 33-byte compressed public key")
    print("pubkey:  ", pub.hex())
    print("address: ", keeta_address(pub))

if __name__ == "__main__":
    main()
