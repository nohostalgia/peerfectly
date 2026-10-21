//! `peerfectly-relay`: a convesso relay, and the key it serves over HTTPS.
//!
//! Configured by environment, each value defaulted (`relay_server::Settings`):
//! `PEERFECTLY_DATA`, `PEERFECTLY_RELAY_LISTEN`, `PEERFECTLY_KEY_LISTEN`,
//! `PEERFECTLY_PUBLIC_PORT`, `PEERFECTLY_RELAY_CONFIG`.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let settings = match relay_server::Settings::from_env() {
        Ok(settings) => settings,
        Err(refusal) => {
            eprintln!("peerfectly-relay: {refusal}");
            return ExitCode::FAILURE;
        }
    };
    let running = match relay_server::start(&settings).await {
        Ok(running) => running,
        Err(refusal) => {
            eprintln!("peerfectly-relay: {refusal}");
            return ExitCode::FAILURE;
        }
    };
    if running.created {
        println!("created a new identity in {}", settings.data.join("relay.key").display());
    }
    // The line a person compares the key with, when a device founds a network
    // on this relay's host.
    println!("relay key {}", running.key);
    println!(
        "relay on udp {} and tcp {}; its key over https on {}",
        running.relay_udp, running.relay_tcp, running.key_at
    );
    match running.serve().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(refusal) => {
            eprintln!("peerfectly-relay: {refusal}");
            ExitCode::FAILURE
        }
    }
}
