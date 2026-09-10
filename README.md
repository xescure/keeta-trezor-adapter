# keeta-trezor

Sign Keeta block hashes with a Trezor Safe 3, and get a rock-solid Keeta
address for the key the device derives. Companion to
[keeta-block-inspector](../keeta-block-inspector), which reviews the block and
publishes it; this tool only signs.

The key is a P-256 key derived on the Trezor via SLIP-0013 `SignIdentity`
(`gpg://keeta@keeta`, index 0 by default). The Trezor signs blind: it shows
"Sign GPG", the identity, and a short prefix of the block hash. Everything
about *what* the block does is checked in the inspector before you copy the
hash.

## Setup ceremony (once per account)

1. Decide the identity (defaults `--user keeta --host keeta`) and index.
   Write `gpg://keeta@keeta`, the index, and `nist256p1` next to your seed backup.
2. `keeta-trezor address --index N`. Confirm "Sign GPG" with `keeta@keeta` on
   the device. Write the printed address on paper.
   If your seed uses a passphrase, the device asks for it on its own screen;
   the tool never takes a passphrase. A different passphrase gives a
   different key and address, which `--expect` catches on later runs.
3. Cross-check with the independent Python script:
   `python3 recovery/keeta_trezor_address.py --identity gpg://keeta@keeta --index N --pubkey <pubkey hex>`
   The address must match.
4. Fund only the paper address. Testnet first.

Multiple accounts: keep the identity, bump `--index`. Each index is an
independent key. The index is not shown on the device, so the terminal and
your paper record are what tell them apart. `keeta-trezor address --index N`
also prints the derivation path; record it with the address.

## Signing (per transaction)

1. Online: write a draft with the Trezor address as account and signer, run
   `npm run propose` in the inspector project, keep the proposal JSON and hash.
2. Offline: paste the JSON into `keeta-block-inspector.html`, read every
   operation, confirm the hash.
3. `keeta-trezor sign <hash> --expect <address> [--index N]`. Type the last 6
   hex chars of the hash. Check the device shows the same identity and hash
   prefix, confirm.
4. Copy the printed line (`address signature`) into the publisher's
   signatures box together with the proposal JSON. Assemble, Transmit.

`--expect` pins the signing key: if the device returns a different key
(passphrase typo, wrong identity or index), nothing is printed.

## Development

```
devenv shell
check            # fmt, clippy, tests, python vectors
emulator         # terminal 1: trezor-user-env container (docker, host network)
emulator-setup   # terminal 2: start a wiped T3B1 emulator, load the PUBLIC test mnemonic
KEETA_TREZOR_EMULATOR=1 cargo test --locked --test emulator -- --ignored --test-threads=1
```

The emulator tests are `#[ignore]`d and require `--ignored` to run; without
it (or without `KEETA_TREZOR_EMULATOR=1`), `cargo test` reports them as
skipped rather than passed, so a plain test run cannot be mistaken for a real
emulator run.

The emulator tests press the device button through its debuglink port
themselves. Do not use trezor-user-env's `emulator-press-yes` while the tool
is waiting on the device: the controller pings the device port first and the
emulator then answers the controller instead of the tool.

Entering the shell refreshes `~/.cargo/bin/rustfmt` to point at the shell's
rustfmt (the Keeta ASN.1 build script needs it there). On a machine that uses
rustup, that replaces the rustup shim.

Verified on the emulator (firmware 2.12.4, T3B1): the returned key matches
the handoff vector, and a signature produced this way verifies with both the
Rust and the JS Keeta SDK.

Note on the Python `ecdsa` package: nixpkgs flags it for CVE-2024-23342 (a
timing side channel when *signing*). The recovery script only derives keys,
offline, in break-glass mode, so `devenv.yaml` permits the package.
