{ pkgs, ... }:
{
  packages = [
    pkgs.cargo
    pkgs.rustc
    pkgs.clippy
    pkgs.rustfmt
    pkgs.rust-analyzer
    pkgs.pkg-config
    pkgs.libusb1
    pkgs.websocat
    (pkgs.python3.withPackages (ps: [ ps.ecdsa ]))
  ];

  env.RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";

  # rasn-compiler (used by keetanetwork-asn1's build script) only finds rustfmt at
  # $CARGO_HOME/bin/rustfmt or beside the cargo binary. On Nix those are separate
  # store paths, so without this the generated ASN.1 code is left unformatted and
  # keetanetwork-asn1 fails to compile with "cannot find `Operation` in `gen`".
  # CARGO_HOME must also be exported explicitly: rasn-compiler reads the env var
  # directly rather than falling back to the conventional ~/.cargo default, and
  # devenv does not set CARGO_HOME on its own.
  enterShell = ''
    export CARGO_HOME="$HOME/.cargo"
    mkdir -p "$CARGO_HOME/bin"
    ln -sfn "$(command -v rustfmt)" "$CARGO_HOME/bin/rustfmt"
  '';

  scripts.check.exec = ''
    set -e
    cargo fmt --check
    cargo clippy --locked --all-targets -- -D warnings
    cargo test --locked
    python3 recovery/keeta_trezor_address.py --self-test
  '';

  scripts.py-test.exec = "python3 recovery/keeta_trezor_address.py --self-test";

  # Trezor Safe 3 (T3B1) emulator from trezor-user-env. Foreground; Ctrl-C stops it.
  scripts.emulator.exec = ''
    exec docker run --rm --network host --name trezor-user-env ghcr.io/trezor/trezor-user-env
  '';

  # Start a wiped T3B1 emulator and load the PUBLIC test mnemonic (no PIN, no passphrase).
  # Run after `emulator` is up. Test-only seed; never load a real seed this way.
  scripts.emulator-setup.exec = ''
    set -e
    send() { (echo "$1"; sleep "$2") | websocat -t ws://127.0.0.1:9001 | grep -v '"firmwares"'; }
    send '{"type":"emulator-start","model":"T3B1","version":"-latest","wipe":true}' 10
    send '{"type":"emulator-setup","mnemonic":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about","pin":"","passphrase_protection":false,"label":"keeta-test","needs_backup":false}' 8
    send '{"type":"background-check"}' 2
  '';
}
