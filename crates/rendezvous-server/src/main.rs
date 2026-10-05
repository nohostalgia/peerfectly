//! `peerfectly-rendezvous`: the rendezvous, served over TLS. See the library.

#[tokio::main]
async fn main() -> std::process::ExitCode {
    use std::process::ExitCode;

    let asked = match rendezvous_server::Asked::from_words(std::env::args().skip(1), |name| {
        std::env::var(name).ok()
    }) {
        Ok(asked) => asked,
        Err(refusal) => {
            eprintln!("{refusal}");
            return ExitCode::FAILURE;
        }
    };
    let tls = match rendezvous_server::tls(&asked.cert, &asked.key) {
        Ok(tls) => tls,
        Err(refusal) => {
            eprintln!("{refusal}");
            return ExitCode::FAILURE;
        }
    };
    let listener = match tokio::net::TcpListener::bind(asked.listen).await {
        Ok(listener) => listener,
        Err(cause) => {
            eprintln!("{} could not be listened on: {cause}", asked.listen);
            return ExitCode::FAILURE;
        }
    };

    // The one line it writes: where, and with which certificate.
    eprintln!("peerfectly-rendezvous listening on {} with {}", asked.listen, asked.cert.display());

    match rendezvous_server::serve(listener, tls).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(cause) => {
            eprintln!("serving stopped: {cause}");
            ExitCode::FAILURE
        }
    }
}
