//! Runs only with KEETA_TREZOR_EMULATOR=1 against a trezor-user-env T3B1
//! emulator (`devenv shell -- emulator`, then `emulator-setup`) loaded with
//! the public `abandon … about` mnemonic, no passphrase.
//!
//! Button presses go straight to the emulator's debuglink UDP port. The
//! trezor-user-env controller's `emulator-press-yes` must NOT be used while
//! the binary is mid-call: it pings the device port from its own socket and
//! the emulator then answers the controller instead of us.

use std::net::UdpSocket;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_keeta-trezor");
const DEBUGLINK: &str = "127.0.0.1:21325";
const ADDRESS: &str = "keeta_aybuviimr6wejcmwfdgmcmxlofrpmperfz57g4v3whoiu2mrb3rghdc2med7ibi";
const PUBKEY: &str = "034aa10c8fac44899628ccc132eb7162f63c912e7bf372bbb1dc8a69910ee2638c";
const HASH: &str = "8f2c3a1d9e4b7c6a5d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e";

fn enabled() -> bool {
    std::env::var("KEETA_TREZOR_EMULATOR").as_deref() == Ok("1")
}

/// One v1-framed DebugLinkDecision { button: YES } datagram to the debuglink port.
fn press_yes() {
    let payload = [0x08u8, 0x01];
    let mut frame = Vec::with_capacity(64);
    frame.extend_from_slice(b"?##");
    frame.extend_from_slice(&100u16.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame.resize(64, 0);
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.send_to(&frame, DEBUGLINK).unwrap();
}

/// Run the binary with `args`, pressing YES on the device once it is waiting.
fn run(args: &[&str]) -> std::process::Output {
    let mut child = Command::new(BIN)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let mut presses = 0;
    let output = loop {
        thread::sleep(Duration::from_secs(3));
        if child.try_wait().unwrap().is_some() {
            break child.wait_with_output().unwrap();
        }
        if presses < 3 {
            press_yes();
            presses += 1;
        }
        assert!(
            start.elapsed() < Duration::from_secs(40),
            "binary did not finish; is the emulator loaded?"
        );
    };
    output
}

#[test]
#[ignore = "needs KEETA_TREZOR_EMULATOR=1 and a running trezor-user-env emulator"]
fn address_matches_handoff_vector() {
    if !enabled() {
        eprintln!("skipped: set KEETA_TREZOR_EMULATOR=1");
        return;
    }
    let out = run(&[
        "address",
        "--user",
        "keeta-cold",
        "--host",
        "vault",
        "--index",
        "0",
        "--expect",
        ADDRESS,
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains(PUBKEY), "stdout: {stdout}");
    assert!(stdout.contains(ADDRESS), "stdout: {stdout}");
}

#[test]
#[ignore = "needs KEETA_TREZOR_EMULATOR=1 and a running trezor-user-env emulator"]
fn sign_produces_verifiable_line() {
    if !enabled() {
        eprintln!("skipped: set KEETA_TREZOR_EMULATOR=1");
        return;
    }
    let out = run(&[
        "sign",
        HASH,
        "--user",
        "keeta-cold",
        "--host",
        "vault",
        "--index",
        "0",
        "--expect",
        ADDRESS,
        "--yes",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.trim();
    let (addr, sig) = line.split_once(' ').expect("address<space>signature");
    assert_eq!(addr, ADDRESS);
    assert_eq!(sig.len(), 128);
    assert!(hex::decode(sig).is_ok());
    assert_eq!(stdout.lines().count(), 1, "stdout must be exactly one line");
    assert!(String::from_utf8_lossy(&out.stderr).contains("verified : ok"));
}

#[test]
#[ignore = "needs KEETA_TREZOR_EMULATOR=1 and a running trezor-user-env emulator"]
fn sign_with_wrong_expect_fails_and_prints_nothing() {
    if !enabled() {
        eprintln!("skipped: set KEETA_TREZOR_EMULATOR=1");
        return;
    }
    // index 1 derives a different key, so the pinned address must not match.
    let out = run(&[
        "sign",
        HASH,
        "--user",
        "keeta-cold",
        "--host",
        "vault",
        "--index",
        "1",
        "--expect",
        ADDRESS,
        "--yes",
    ]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty(), "stdout must be empty on failure");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("expected keeta_ayb"), "stderr: {stderr}");
}
