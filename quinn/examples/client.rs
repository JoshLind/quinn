//! This example demonstrates an HTTP client that requests files from a server.
//!
//! Checkout the `README.md` for guidance.

use std::{
    fs,
    io::{self},
    net::ToSocketAddrs,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use clap::Parser;
use tracing::{error, info};
use url::Url;

mod common;

/// HTTP/0.9 over QUIC client
#[derive(Parser, Debug)]
#[clap(name = "client")]
struct Opt {
    /// Perform NSS-compatible TLS key logging to the file specified in `SSLKEYLOGFILE`.
    #[clap(long = "keylog")]
    keylog: bool,

    url: Url,

    /// Override hostname used for certificate verification
    #[clap(long = "host")]
    host: Option<String>,

    /// Custom certificate authority to trust, in DER format
    #[clap(long = "ca")]
    ca: Option<PathBuf>,

    /// Simulate NAT rebinding after connecting
    #[clap(long = "rebind")]
    rebind: bool,
}

fn main() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();
    let opt = Opt::parse();
    let code = {
        if let Err(e) = run(opt) {
            println!("ERROR: {e}");
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}

#[tokio::main]
async fn run(options: Opt) -> Result<()> {
    // Get the remote URL string and port
    let url_string = options.url.host_str().unwrap();
    let url_port = options.url.port().unwrap_or(4433);
    let remote_host = (url_string, url_port);

    // Get the remote socket address
    let remote_socket_addr = remote_host
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;

    // Gather the root certificates for the client
    let mut roots = rustls::RootCertStore::empty();
    if let Some(ca_path) = options.ca {
        roots.add(&rustls::Certificate(fs::read(ca_path)?))?;
    } else {
        let dirs = directories_next::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
        match fs::read(dirs.data_local_dir().join("cert.der")) {
            Ok(cert) => {
                roots.add(&rustls::Certificate(cert))?;
            }
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!("local server certificate not found");
            }
            Err(e) => {
                error!("failed to open local server certificate: {}", e);
            }
        }
    }

    // Create the crypto client config using the root certificates and specified options
    let mut crypto_client_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto_client_config.alpn_protocols =
        common::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    if options.keylog {
        crypto_client_config.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    // Create the QUIC client config
    let client_config = quinn::ClientConfig::new(Arc::new(crypto_client_config));
    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_config);

    // Identify the remote host
    let host_string = options
        .host
        .as_ref()
        .map_or_else(|| options.url.host_str(), |x| Some(x))
        .ok_or_else(|| anyhow!("no hostname specified"))?;

    // Connect to the remote host
    println!("Connecting to {} at {:?}", host_string, remote_host);
    let start = Instant::now();
    let connection = endpoint
        .connect(remote_socket_addr, host_string)?
        .await
        .map_err(|e| anyhow!("failed to connect: {}", e))?;

    // Open the bi-directional stream
    println!("Connected to {host_string} in {:?}", start.elapsed());
    let (mut send_stream, mut receive_stream) = connection
        .open_bi()
        .await
        .map_err(|e| anyhow!("failed to open stream: {}", e))?;

    // Simulate NAT rebinding after connecting
    if options.rebind {
        let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
        let addr = socket.local_addr().unwrap();
        println!("rebinding to {addr}");
        endpoint.rebind(socket).expect("rebind failed");
    }

    // Send the GET request to the server
    let request = format!("GET {}\r\n", options.url.path());
    send_stream.write_all(request.as_bytes())
        .await
        .map_err(|e| anyhow!("failed to send request: {}", e))?;
    send_stream.finish()
        .await
        .map_err(|e| anyhow!("failed to shutdown stream: {}", e))?;
    let response_start = Instant::now();
    println!("Request sent at {:?}", response_start - start);

    // Get the response
    let resp = receive_stream
        .read_to_end(usize::max_value())
        .await
        .map_err(|e| anyhow!("failed to read response: {}", e))?;
    let duration = response_start.elapsed();
    println!(
        "Response received in {:?} - {} KiB/s",
        duration,
        resp.len() as f32 / (duration_secs(&duration) * 1024.0)
    );

    // Print the response
    println!("Received {} bytes", resp.len());
    println!("Response: {:?}", resp);

    // Close the connection
    connection.close(0u32.into(), b"done");

    // Give the server a fair chance to receive the close packet
    endpoint.wait_idle().await;

    Ok(())
}

fn duration_secs(x: &Duration) -> f32 {
    x.as_secs() as f32 + x.subsec_nanos() as f32 * 1e-9
}
