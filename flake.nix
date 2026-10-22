{
  description = "keeta-trezor: sign Keeta block hashes with a Trezor Safe 3";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, crane }:
    let
      forAll = f: nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ]
        (s: f nixpkgs.legacyPackages.${s});

      perSystem = pkgs:
        let
          inherit (pkgs) lib;
          cargoToml = (lib.importTOML ./Cargo.toml).package;

          # cargo, rustc, rustfmt and clippy in one directory: rasn-compiler
          # (keetanetwork-asn1's build script) finds rustfmt only next to
          # $CARGO or in $CARGO_HOME/bin, and on Nix these are separate store
          # paths. Without it the generated ASN.1 code is left unformatted and
          # keetanetwork-asn1 fails with "cannot find `Operation` in `gen`".
          # The build, the checks and the development shell all use it.
          rustToolchain = pkgs.symlinkJoin {
            name = "rust-toolchain";
            paths = with pkgs; [ cargo rustc rustfmt clippy ];
          };
          craneLib = (crane.mkLib pkgs).overrideToolchain (_: rustToolchain);

          src = craneLib.cleanCargoSource ./.;

          # keetanetwork-asn1's build script rewrites src/generated.rs inside its
          # own crate directory, which is read-only in the Nix store. The copy in
          # the crate is already the right one (it only include!s files from
          # OUT_DIR), so send the rewrite to OUT_DIR instead.
          cargoVendorDir = craneLib.vendorCargoDeps {
            cargoLock = ./Cargo.lock;
            overrideVendorCargoPackage = p: drv:
              if p.name == "keetanetwork-asn1" then
                drv.overrideAttrs (_: {
                  postPatch = ''
                    substituteInPlace build.rs --replace-fail \
                      '.with_public_modules(vec!["iso20022"]);' \
                      '.with_public_modules(vec!["iso20022"]).with_generated_rs_path(&format!("{out_dir}/generated.rs"));'
                  '';
                })
              else drv;
          };

          commonArgs = {
            inherit src cargoVendorDir;
            pname = cargoToml.name;
            inherit (cargoToml) version;
            strictDeps = true;
            cargoExtraArgs = "--locked";
            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [ pkgs.libusb1 ];
          };

          # Dependencies compiled once, shared by the binary, clippy and the tests.
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;

          keeta-trezor = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;
            doCheck = false; # the tests are checks.tests
            nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ pkgs.installShellFiles ];
            postInstall = lib.optionalString (pkgs.stdenv.buildPlatform.canExecute pkgs.stdenv.hostPlatform) ''
              installShellCompletion --cmd keeta-trezor \
                --bash <($out/bin/keeta-trezor completions bash) \
                --fish <($out/bin/keeta-trezor completions fish) \
                --zsh <($out/bin/keeta-trezor completions zsh)
            '';
            meta = {
              mainProgram = "keeta-trezor";
              license = lib.licenses.mpl20;
            };
          });

          # The recovery script's Python. ecdsa is flagged for CVE-2024-23342, a
          # timing side channel in signing; the script only derives keys, so it
          # is permitted here, for the script alone.
          recoveryPython = (import nixpkgs {
            inherit (pkgs.stdenv.hostPlatform) system;
            config.allowInsecurePredicate = p: (p.pname or null) == "ecdsa";
          }).python3.withPackages (ps: [ ps.ecdsa ]);
        in
        {
          packages.default = keeta-trezor;

          checks = {
            fmt = craneLib.cargoFmt { inherit src; pname = cargoToml.name; };
            clippy = craneLib.cargoClippy (commonArgs // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets -- -D warnings";
            });
            # The emulator tests are #[ignore]d: they need trezor-user-env.
            tests = craneLib.cargoTest (commonArgs // { inherit cargoArtifacts; });
            # The recovery script's own vectors, independent of the Rust tool.
            recovery = pkgs.runCommand "keeta-trezor-recovery-self-test" { } ''
              ${recoveryPython}/bin/python3 ${./recovery/keeta_trezor_address.py} --self-test
              touch $out
            '';
          };

          devShells.default = craneLib.devShell {
            checks = self.checks.${pkgs.stdenv.hostPlatform.system};
            packages = [
              pkgs.rust-analyzer
              pkgs.websocat
              recoveryPython
              # Trezor Safe 3 (T3B1) emulator from trezor-user-env. Foreground; Ctrl-C stops it.
              (pkgs.writeShellScriptBin "emulator" ''
                exec docker run --rm --network host --name trezor-user-env ghcr.io/trezor/trezor-user-env
              '')
              # Start a wiped T3B1 emulator and load the PUBLIC test mnemonic (no PIN, no
              # passphrase). Run after `emulator` is up. Test-only seed; never load a real seed this way.
              (pkgs.writeShellScriptBin "emulator-setup" ''
                set -e
                send() { (echo "$1"; sleep "$2") | ${pkgs.websocat}/bin/websocat -t ws://127.0.0.1:9001 | grep -v '"firmwares"'; }
                send '{"type":"emulator-start","model":"T3B1","version":"-latest","wipe":true}' 10
                send '{"type":"emulator-setup","mnemonic":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about","pin":"","passphrase_protection":false,"label":"keeta-test","needs_backup":false}' 8
                send '{"type":"background-check"}' 2
              '')
            ];
            RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
          };
        };
    in
    {
      packages = forAll (pkgs: (perSystem pkgs).packages);
      checks = forAll (pkgs: (perSystem pkgs).checks);
      devShells = forAll (pkgs: (perSystem pkgs).devShells);
    };
}
