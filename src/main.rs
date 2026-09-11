mod cli;
mod error;
mod identity;
mod keeta;
mod trezor;

use std::io::{self, BufRead, Write};
use std::process::ExitCode;

use clap::{Args, CommandFactory, Parser, Subcommand};

use crate::error::{Error, Result};
use crate::identity::Identity;

/// Sign Keeta block hashes with a Trezor Safe 3 (SLIP-0013 P-256 identity key).
#[derive(Parser)]
#[command(name = "keeta-trezor", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct IdentityArgs {
    /// SLIP-0013 identity user part (gpg://USER@host)
    #[arg(long, default_value = "keeta")]
    user: String,
    /// SLIP-0013 identity host part (gpg://user@HOST)
    #[arg(long, default_value = "keeta")]
    host: String,
    /// SLIP-0013 index; use 1, 2, ... for additional accounts
    #[arg(long, default_value_t = 0)]
    index: u32,
}

impl IdentityArgs {
    fn identity(&self) -> Identity {
        Identity {
            user: self.user.clone(),
            host: self.host.clone(),
            index: self.index,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Print the identity, derivation path, public key, and Keeta address from the device.
    Address {
        #[command(flatten)]
        id: IdentityArgs,
        /// Fail unless the device address equals this one.
        #[arg(long)]
        expect: Option<String>,
    },
    /// Sign a Keeta block hash. Prints one line: `<address> <signature hex>`.
    Sign {
        /// 32-byte block hash, hex, as shown by the block inspector.
        block_hash: String,
        #[command(flatten)]
        id: IdentityArgs,
        /// The address that must sign (from your setup record). Pins the device key.
        #[arg(long)]
        expect: String,
        /// Skip the typed confirmation. For the emulator test only.
        #[arg(long)]
        yes: bool,
    },
    /// Print a shell completion script. Run by the Nix package build.
    #[command(hide = true)]
    Completions { shell: clap_complete::Shell },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Address { id, expect } => run_address(&id.identity(), expect.as_deref()),
        Command::Sign {
            block_hash,
            id,
            expect,
            yes,
        } => run_sign(&block_hash, &id.identity(), &expect, yes),
        Command::Completions { shell } => {
            write_completions(shell, &mut io::stdout());
            Ok(())
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_identity(identity: &Identity) {
    eprintln!("identity : {}", identity.identity_string());
    eprintln!("index    : {}", identity.index);
    eprintln!("curve    : {}", Identity::CURVE);
    eprintln!("path     : {}", identity.path_string());
}

fn run_address(identity: &Identity, expect: Option<&str>) -> Result<()> {
    let expected = expect.map(keeta::pubkey_from_address).transpose()?;
    print_identity(identity);
    eprintln!(
        "Confirm 'Sign GPG' with '{}' on the device.",
        identity.display_string()
    );
    let challenge = keeta::sha3_256(cli::PUBKEY_FETCH_DOMAIN);
    let reply = trezor::sign_identity(identity, challenge, "KEY SETUP ONLY")?;
    let address = keeta::address_from_pubkey(&reply.pubkey)?;
    if let (Some(exp), Some(exp_addr)) = (expected, expect) {
        if exp != reply.pubkey {
            return Err(Error::UnexpectedKey {
                got: address,
                expected: exp_addr.to_string(),
            });
        }
    }
    println!("pubkey   : {}", hex::encode(reply.pubkey));
    println!("address  : {address}");
    Ok(())
}

fn run_sign(block_hash_hex: &str, identity: &Identity, expect: &str, yes: bool) -> Result<()> {
    let block_hash = cli::parse_block_hash(block_hash_hex)?;
    let expected_pubkey = keeta::pubkey_from_address(expect)?;
    let hash_hex = hex::encode(block_hash);

    print_identity(identity);
    eprintln!("signer   : {expect}");
    eprintln!("hash     : {hash_hex}");
    eprintln!("device   : {}", cli::visual_summary(&block_hash));

    if !yes {
        eprint!("Type the last 6 hex characters of the hash to confirm: ");
        io::stderr().flush().ok();
        let mut typed = String::new();
        io::stdin()
            .lock()
            .read_line(&mut typed)
            .map_err(|e| Error::BadInput(e.to_string()))?;
        if !cli::confirmation_matches(&block_hash, &typed) {
            return Err(Error::BadInput(
                "confirmation did not match; nothing signed".into(),
            ));
        }
    }

    eprintln!(
        "Confirm 'Sign GPG' with '{}' and the same hash prefix on the device.",
        identity.display_string()
    );
    let digest = keeta::sha3_256(&block_hash);
    let reply = trezor::sign_identity(identity, digest, &cli::visual_summary(&block_hash))?;

    if reply.pubkey != expected_pubkey {
        let got = keeta::address_from_pubkey(&reply.pubkey)
            .unwrap_or_else(|_| format!("pubkey {}", hex::encode(reply.pubkey)));
        return Err(Error::UnexpectedKey {
            got,
            expected: expect.to_string(),
        });
    }
    keeta::verify_block_signature(&reply.pubkey, &block_hash, &reply.signature)?;

    let address = keeta::address_from_pubkey(&reply.pubkey)?;
    eprintln!("verified : ok");
    println!("{address} {}", hex::encode(reply.signature));
    Ok(())
}

fn write_completions(shell: clap_complete::Shell, out: &mut dyn Write) {
    let mut buf = Vec::new();
    clap_complete::generate(shell, &mut Cli::command(), "keeta-trezor", &mut buf);
    let mut script = String::from_utf8(buf).expect("clap_complete emits UTF-8");
    if shell == clap_complete::Shell::Bash {
        // clap_complete 4.6.9 escapes the `-` in `keeta-trezor` as `__` in the dispatch
        // (`cmd="keeta__trezor__subcmd__sign"`) but as `__subcmd__` in the case labels,
        // so subcommand flags never complete. Align the labels with the dispatch.
        script = script.replace("keeta__subcmd__trezor", "keeta__trezor");
    }
    out.write_all(script.as_bytes())
        .expect("writing completion script");
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap_complete::Shell;

    fn completion(shell: Shell) -> String {
        let mut out = Vec::new();
        write_completions(shell, &mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn bash_completion_offers_subcommands_and_flags() {
        let script = completion(Shell::Bash);
        for word in ["address", "sign", "--expect", "--index", "--user", "--host"] {
            assert!(script.contains(word), "missing {word}");
        }
    }

    #[test]
    fn bash_completion_dispatch_matches_case_labels() {
        let script = completion(Shell::Bash);
        let names: Vec<&str> = script
            .lines()
            .filter_map(|l| l.trim().strip_prefix("cmd=\""))
            .map(|rest| rest.trim_end_matches('"'))
            .filter(|name| !name.is_empty())
            .collect();
        assert!(names.contains(&"keeta__trezor__subcmd__sign"));
        for name in names {
            let label = format!("{name})");
            assert!(
                script.lines().any(|l| l.trim() == label),
                "no case for {name}"
            );
        }
    }

    #[test]
    fn completions_subcommand_is_hidden_from_help() {
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("address"));
        assert!(!help.contains("completions"));
    }
}
