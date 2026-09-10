mod cli;
mod error;
mod identity;
mod keeta;
mod trezor;

use std::io::{self, BufRead, Write};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

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
    print_identity(identity);
    let expected = expect.map(keeta::pubkey_from_address).transpose()?;
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
        let got = keeta::address_from_pubkey(&reply.pubkey)?;
        return Err(Error::UnexpectedKey {
            got,
            expected: expect.to_string(),
        });
    }
    keeta::verify_block_signature(&reply.pubkey, &block_hash, &reply.signature)?;

    eprintln!("verified : ok");
    println!("{expect} {}", hex::encode(reply.signature));
    Ok(())
}
