//! `peerfectly board`: one board provisioned and admitted with one command,
//! over its cable (`scalable-membership` 15.8).
//!
//! The same lines as the production station, read and written here: the
//! board's public keys and serial in; what the network's boards start from
//! out, from this machine's daemon; the digest the board answers checked; then
//! the board shown and, on a yes, admitted as a batch of one, signed as any
//! admission is. The board's private keys never cross the cable. A board on a
//! computer is reached with `--port tcp:host:port`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use daemon::control::{BATCH_FORMAT, BatchDevice, BatchFile, Command, Outcome};
use light_node::provision::{ANCHORS_GIVEN, Given, Line};
use roster::id::DeviceId;
use roster::membership::Evidence;
use roster::types::NetworkParams;

use crate::{AdmittingAsked, Cli};

/// How it is written.
pub(crate) const BOARD_USAGE: &str = "peerfectly board --network <network> [--port <serial port | tcp:host:port>] \
                                      [--name <name>] [--full]";

/// How long a board is waited for, for its keys or for its answer.
const PATIENCE: Duration = Duration::from_secs(30);

/// How many times what a board starts from is sent, when its answer is missed.
const SENDS: usize = 3;

/// How long a board's answer is waited for, after each sending: its key lines
/// in the meantime are passed over.
const ANSWER: Duration = Duration::from_secs(20);

/// What is written to the board at once, and the pause after it. A board's
/// serial port takes a few hundred bytes before its program reads them (256 on
/// an ESP32's own USB, by default), and drops what comes past them: what a
/// board starts from is tens of kilobytes, sent at about 12 KB/s.
const PIECE: usize = 128;
const PAUSE: Duration = Duration::from_millis(10);

/// How long a board admitted is waited for, before saying it joins later.
const JOINING: Duration = Duration::from_secs(180);

/// How often, while it is waited for, the board is looked for.
const LOOKED_EVERY: Duration = Duration::from_secs(2);

/// What `board` was asked for.
struct Asked {
    network: String,
    port: Option<String>,
    name: Option<String>,
    full: bool,
}

fn asked_from(words: &[String]) -> Result<Asked, String> {
    let usage = || format!("usage: {BOARD_USAGE}");
    let mut network = None;
    let mut asked = Asked { network: String::new(), port: None, name: None, full: false };
    let mut rest = words.iter();
    while let Some(word) = rest.next() {
        match word.as_str() {
            "--network" => network = Some(rest.next().ok_or_else(usage)?.clone()),
            "--port" => asked.port = Some(rest.next().ok_or_else(usage)?.clone()),
            "--name" => asked.name = Some(rest.next().ok_or_else(usage)?.clone()),
            "--full" => asked.full = true,
            _ => return Err(usage()),
        }
    }
    asked.network = network.ok_or_else(usage)?;
    Ok(asked)
}

/// The board's cable.
trait Cable: Read + Write + Send {}
impl<T: Read + Write + Send> Cable for T {}

/// The one board attached by USB, where there is exactly one.
fn the_board() -> Result<String, String> {
    let ports = serialport::available_ports().map_err(|cause| {
        format!("the serial ports could not be listed ({cause}): name one with --port")
    })?;
    let boards: Vec<String> = ports
        .into_iter()
        .filter(|port| {
            matches!(port.port_type, serialport::SerialPortType::UsbPort(_))
                || port.port_name.contains("ttyUSB")
                || port.port_name.contains("ttyACM")
                || port.port_name.contains("cu.usb")
        })
        .map(|port| port.port_name)
        .collect();
    match boards.as_slice() {
        [one] => Ok(one.clone()),
        [] => {
            Err("no board is attached by USB: plug it in, or name its port with --port".to_owned())
        }
        many => Err(format!(
            "more than one serial port: name the board's with --port ({})",
            many.join(", ")
        )),
    }
}

/// Opens the cable, without moving DTR or RTS: on many boards they reset it.
fn open(port: &str) -> Result<Box<dyn Cable>, String> {
    if let Some(address) = port.strip_prefix("tcp:") {
        let stream =
            std::net::TcpStream::connect(address).map_err(|cause| format!("{address}: {cause}"))?;
        let _ = stream.set_read_timeout(Some(PATIENCE));
        return Ok(Box::new(stream));
    }
    let serial =
        serialport::new(port, 115_200).timeout(PATIENCE).dtr_on_open(false).open().map_err(
            |cause| match cause.kind() {
                serialport::ErrorKind::NoDevice => format!("{port}: no such port"),
                _ => format!(
                    "{port}: {cause}. Is the serial monitor open? It holds the port: close it"
                ),
            },
        )?;
    Ok(Box::new(serial))
}

/// The next line of ours the board says, skipping everything else it writes.
fn next_line(reader: &mut BufReader<Box<dyn Cable>>) -> Result<Line, String> {
    loop {
        let mut text = String::new();
        match reader.read_line(&mut text) {
            Ok(0) => return Err("the board went away".to_owned()),
            Ok(_) => {
                if let Some(line) = Line::parse(text.trim()) {
                    return Ok(line);
                }
            }
            Err(cause)
                if matches!(
                    cause.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err("the board says nothing".to_owned());
            }
            Err(cause) => return Err(format!("reading the board: {cause}")),
        }
    }
}

/// The relay, as an address a board can reach with no name to resolve.
fn relay(written: &str) -> Result<([u8; 32], SocketAddr), String> {
    if written.starts_with("tls://") {
        return Err(
            "the network's relay is reached over TLS, which a board does not speak".to_owned()
        );
    }
    let (key, host) = written.split_once('@').ok_or("the network's relay does not read")?;
    let key: [u8; 32] = roster::hex::decode(key)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or("the relay's key does not read")?;
    let addresses: Vec<SocketAddr> =
        host.to_socket_addrs().map_err(|cause| format!("{host}: {cause}"))?.collect();
    let address = addresses
        .iter()
        .find(|address| address.is_ipv4())
        .or_else(|| addresses.first())
        .copied()
        .ok_or_else(|| format!("{host} resolves to nothing"))?;
    Ok((key, address))
}

fn bytes(text: &str, what: &str) -> Result<Vec<u8>, String> {
    roster::hex::decode(text).ok_or_else(|| format!("the daemon's {what} does not read"))
}

/// What the board said: its public keys and serial.
struct Board {
    signing: [u8; 32],
    transport: [u8; 32],
    attestation: [u8; 32],
    serial: Vec<u8>,
}

impl Cli<'_> {
    /// Provisions the one board on the cable for a network, and admits it.
    pub(crate) async fn board(&self, words: &[String]) -> ExitCode {
        match self.board_or_why(words).await {
            Ok(code) => code,
            Err(why) => {
                eprintln!("{why}");
                ExitCode::FAILURE
            }
        }
    }

    async fn board_or_why(&self, words: &[String]) -> Result<ExitCode, String> {
        let asked = asked_from(words)?;
        self.custody.may_sign().map_err(|refusal| refusal.to_string())?;
        let port = match &asked.port {
            Some(port) => port.clone(),
            None => the_board()?,
        };
        let mut cable = BufReader::new(open(&port)?);

        // The board, as it says itself every two seconds while it waits.
        println!("waiting for the board on {port}…");
        let board = match next_line(&mut cable) {
            Ok(Line::Keys { signing, transport, attestation, serial }) => {
                Board { signing, transport, attestation, serial }
            }
            Ok(_) | Err(_) => {
                return Err(format!(
                    "the board on {port} does not say its keys: is it provisioned already? A \
                     provisioned board takes no other network; erase its partition (or call \
                     `Peerfectly.forget()`) to make it a new device"
                ));
            }
        };

        // What every board of the network starts from, from this machine's daemon.
        let provisioning =
            match self.ask(Command::Provisioning { network: Some(asked.network.clone()) }).await {
                Ok(Outcome::Provisioning(provisioning)) => provisioning,
                Ok(
                    Outcome::NotAllowed { message }
                    | Outcome::Declined { message }
                    | Outcome::Failed { message, .. },
                ) => {
                    return Err(message);
                }
                Ok(other) => return Err(format!("unexpected answer from the daemon: {other:?}")),
                Err(cause) => return Err(cause.to_string()),
            };
        let params_bytes = bytes(&provisioning.params, "parameters")?;
        let params =
            NetworkParams::from_bytes(&params_bytes).map_err(|_| "the parameters do not read")?;
        let (relay_key, relay_address) = relay(&provisioning.relay)?;
        let device = DeviceId::of_signing_key(&board.signing);
        // The anchors it will turn to, by its own rendezvous; where the network
        // names none, the full members the daemon gave.
        let chosen = light_node::seeking::anchors_for(&device, &params.anchors);
        let mut anchors = Vec::new();
        for text in &provisioning.anchors {
            let evidence = bytes(text, "anchor evidence")?;
            if Evidence::from_bytes(&evidence).is_ok_and(|shown| {
                params.anchors.is_empty() || chosen.contains(&shown.leaf.record.id)
            }) {
                anchors.push(evidence);
            }
        }
        anchors.truncate(ANCHORS_GIVEN);
        let given = Given {
            relay_key,
            relay: relay_address,
            // The sketch connects the board; the firmware is given its link by a station.
            link: String::new(),
            passphrase: String::new(),
            root: bytes(&provisioning.root, "root")?,
            devices_root: bytes(&provisioning.devices_root, "devices root")?
                .try_into()
                .map_err(|_| "the devices root does not read")?,
            params: params_bytes,
            anchors,
        };

        // Sent, and sent again where the answer was missed: the board answers
        // the same again, and refuses anything else.
        let mut taken = false;
        let line = format!("{}\n", Line::Provision(given.clone()).text());
        'sending: for _ in 0..SENDS {
            for piece in line.as_bytes().chunks(PIECE) {
                cable
                    .get_mut()
                    .write_all(piece)
                    .map_err(|cause| format!("writing the board: {cause}"))?;
                let _ = cable.get_mut().flush();
                std::thread::sleep(PAUSE);
            }
            let until = Instant::now().checked_add(ANSWER).unwrap_or_else(Instant::now);
            while Instant::now() < until {
                match next_line(&mut cable) {
                    Ok(Line::Taken(digest)) if digest == given.digest() => {
                        taken = true;
                        break 'sending;
                    }
                    Ok(Line::Taken(_)) => {
                        return Err(
                            "the board took something else than was sent: nothing was admitted"
                                .to_owned(),
                        );
                    }
                    Ok(Line::Refused(why)) => return Err(format!("the board refused: {why}")),
                    // Its key lines, said while it read what was sent.
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
        if !taken {
            return Err("the board did not answer: nothing was admitted. Run it again".to_owned());
        }
        drop(cable);

        // The board, shown, and admitted on a yes.
        let serial = roster::hex::encode(&board.serial);
        let tail = serial.get(serial.len().saturating_sub(6)..).unwrap_or(&serial);
        let name = asked.name.clone().unwrap_or_else(|| format!("board-{tail}"));
        let fingerprint =
            roster::sign::PublicKey::new(roster::types::Algorithm::Ed25519, board.signing.to_vec())
                .map(|key| daemon::joining::fingerprint(&key))
                .unwrap_or_default();
        println!();
        println!("the board on {port} is provisioned for {}:", asked.network);
        println!("  serial      {serial}");
        println!("  key         {fingerprint}");
        println!("  name        {}", daemon::control::shown(&name));
        let file = BatchFile {
            format: BATCH_FORMAT.to_owned(),
            label: format!("board {name}"),
            devices: vec![BatchDevice {
                name: name.clone(),
                serial,
                signing: roster::hex::encode(&board.signing),
                transport: roster::hex::encode(&board.transport),
                attestation: roster::hex::encode(&board.attestation),
            }],
        };
        let admitting = AdmittingAsked {
            file: String::new(),
            network: Some(asked.network.clone()),
            light: !asked.full,
            groups: Vec::new(),
            ipv6_only: false,
        };
        let code = self.admit_devices(&admitting, &file).await;
        if code != ExitCode::SUCCESS {
            return Ok(code);
        }

        // Reached at once: waiting, the board tries again only every thirty
        // seconds, and learns it was admitted from a session with a member.
        let reach = Command::Reach {
            network: asked.network.clone(),
            transport: roster::hex::encode(&board.transport),
        };
        let _reached = self.ask(reach).await;

        // Waited for: `peers` looks at it before it answers.
        println!("waiting for {name} to join…");
        let until = Instant::now().checked_add(JOINING).unwrap_or_else(Instant::now);
        while Instant::now() < until {
            let asked_peers = Command::Peers { network: Some(asked.network.clone()), after: None };
            if let Ok(Outcome::Reported(report)) = self.ask(asked_peers).await {
                let joined =
                    report.networks.iter().flat_map(|network| network.peers.iter()).find(|peer| {
                        peer.reachable && peer.name.split('.').next() == Some(name.as_str())
                    });
                if let Some(peer) = joined {
                    let ipv4 = match &peer.ipv4 {
                        Some(daemon::control::Ipv4State::Held(address)) => format!(", {address}"),
                        _ => String::new(),
                    };
                    println!("{name} is in {}: {}{ipv4}", asked.network, peer.address);
                    return Ok(ExitCode::SUCCESS);
                }
            }
            tokio::time::sleep(LOOKED_EVERY).await;
        }
        println!(
            "{name} is admitted; it joins at its next attempt, once its sketch connects it to the internet."
        );
        Ok(ExitCode::SUCCESS)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn a_network_is_named_and_the_rest_is_optional() {
        let asked = asked_from(&words("--network casa")).unwrap();
        assert_eq!(
            (asked.network.as_str(), asked.port, asked.name, asked.full),
            ("casa", None, None, false)
        );
        let asked = asked_from(&words("--network casa --port COM5 --name sensore --full")).unwrap();
        assert_eq!(asked.port.as_deref(), Some("COM5"));
        assert_eq!(asked.name.as_deref(), Some("sensore"));
        assert!(asked.full);
        assert!(asked_from(&words("--port COM5")).is_err(), "no network");
        assert!(
            asked_from(&words("--network casa --speed 9600")).is_err(),
            "a word it does not know"
        );
    }

    #[test]
    fn a_relay_over_tls_is_refused_and_one_written_out_reads() {
        assert!(relay("tls://relay.example").is_err());
        let (key, address) = relay(&format!("{}@127.0.0.1:8443", "ab".repeat(32))).unwrap();
        assert_eq!(key, [0xab; 32]);
        assert_eq!(address.port(), 8443);
    }
}
