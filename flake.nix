{
  description = "keeta-trezor: sign Keeta block hashes with a Trezor Safe 3";

  # Same nixpkgs rev as devenv.lock, so the packaged binary is built with the
  # exact toolchain the tests ran on. Pinned in the URL: `nix flake update` won't bump it.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/8ce4ef6cb6f871616146b9fe26d2a5ae594e94fe";

  outputs = { self, nixpkgs }:
    let
      forAll = f: nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ]
        (s: f nixpkgs.legacyPackages.${s});
    in {
      packages = forAll (pkgs:
        let
          inherit (pkgs) lib;
          cargo = (lib.importTOML ./Cargo.toml).package;
        in {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = cargo.name;
            inherit (cargo) version;
            src = lib.fileset.toSource {
              root = ./.;
              fileset = lib.fileset.unions [ ./Cargo.toml ./Cargo.lock ./src ./tests ];
            };
            cargoLock.lockFile = ./Cargo.lock;
            nativeBuildInputs = [ pkgs.pkg-config pkgs.rustfmt pkgs.installShellFiles ];
            buildInputs = [ pkgs.libusb1 ];
            # Same workaround as devenv.nix: rasn-compiler only looks for rustfmt in $CARGO_HOME/bin.
            preBuild = ''
              export CARGO_HOME="$NIX_BUILD_TOP/cargo-home"
              mkdir -p "$CARGO_HOME/bin"
              ln -s ${lib.getExe pkgs.rustfmt} "$CARGO_HOME/bin/rustfmt"
            '';
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
          };
        });
    };
}
