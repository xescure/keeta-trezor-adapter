# keeta-trezor

`keeta-trezor` signs [Keeta][keeta] block hashes with a Trezor hardware wallet.
It is a work-in-progress stopgap: Trezor firmware has no Keeta support, so signing goes through the firmware's GPG identity signing (`SignIdentity`, [SLIP-0013][slip13]) instead.
It has been used with a Trezor Safe 3 to sign blocks accepted on the Keeta main network.

## Keys and addresses

The signing key is an ECDSA secp256r1 (`nist256p1`) key derived on the device from a SLIP-0013 identity `gpg://<user>@<host>` and an index.
The defaults are `keeta`, `keeta`, and `0`, and each index is an independent key.
The Keeta address is the type-6 (ECDSA secp256r1) address of the public key the device returns.

## Signing

Keeta verifies a block signature as ECDSA over `SHA3-256(block hash)`.
In GPG mode the device signs `challenge_hidden` as given, so the tool sends `SHA3-256(block hash)` and the result is a signature the network accepts.
The tool verifies the signature with the [Keeta SDK][sdk] before printing it.

The device displays the identity and a prefix of the block hash -- it does not decode the block.
The displayed text (`challenge_visual`) is not bound to the signed bytes, so the screen is only as trustworthy as the host that sent it.

## Usage

```
keeta-trezor address [--user keeta] [--host keeta] [--index 0]
keeta-trezor sign <block hash> --expect <address> [--index 0]
```

`address` prints the identity, derivation path, public key, and Keeta address.
`sign` prints one line, `<address> <signature hex>`, and prints nothing if the device key differs from `--expect` (e.g., a different passphrase, identity, or index).
It asks for the last six hex characters of the hash before contacting the device.
A passphrase is entered on the device; the tool never handles it.

## Recovery

[`recovery/keeta_trezor_address.py`](recovery/keeta_trezor_address.py) derives the same key and address from the mnemonic ([BIP-39][bip39], [SLIP-0010][slip10], SLIP-0013) without the device, and is intended for offline use only.
With `--pubkey` it computes the address from a device public key instead, and `--self-test` runs its test vectors.

## Development

`nix build` builds the binary and runs the unit tests, and `nix run . -- <args>` runs it.
The development shell is [devenv][devenv], where `check` runs formatting, lints, tests, and the recovery script's vectors.
The emulator tests are ignored by default and run against [trezor-user-env][tue]:

```
emulator          # terminal 1
emulator-setup    # terminal 2, loads the public test mnemonic
KEETA_TREZOR_EMULATOR=1 cargo test --locked --test emulator -- --ignored --test-threads=1
```

Entering the shell points `~/.cargo/bin/rustfmt` at the shell's `rustfmt`, which the Keeta ASN.1 build script requires.
`devenv.yaml` permits the Python `ecdsa` package despite CVE-2024-23342, a timing side channel in signing, because the recovery script only derives keys.

## License

[MPL-2.0](LICENSE)

[keeta]: https://keeta.com/
[sdk]: https://crates.io/crates/keetanetwork-account
[slip13]: https://github.com/satoshilabs/slips/blob/master/slip-0013.md
[slip10]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
[bip39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
[devenv]: https://devenv.sh/
[tue]: https://github.com/trezor/trezor-user-env
