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
use std::net::{IpAddr, SocketAddr};

use anyhow::{anyhow, Result};
use clap::Parser;
use proto::{ClientConfig, IdleTimeout, ServerConfig, TransportConfig, VarInt};
use tracing::{error, info};
use url::Url;
use crate::common::SERVER_STRING;

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

    // Create the QUIC server configuration
    let (server_config, _server_certificate) = configure_server()?;

    // Create the QUIC server endpoint
    let socket_addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 62626);
    let mut server_endpoint = quinn::Endpoint::server(server_config, socket_addr)?;
    server_endpoint.set_default_client_config(configure_client()); // Required to skip certificate verification
    println!("Server listening on {}", server_endpoint.local_addr()?);

    // Identify the remote host
    let host_string = options
        .host
        .as_ref()
        .map_or_else(|| options.url.host_str(), |x| Some(x))
        .ok_or_else(|| anyhow!("no hostname specified"))?;

    // Connect to the remote host
    println!("Connecting to {} at {:?}", host_string, remote_host);
    let start = Instant::now();
    let connection = server_endpoint
        .connect(remote_socket_addr, host_string)?
        .await
        .map_err(|e| anyhow!("failed to connect: {}", e))?;

    // Open the uni-directional stream
    println!("Connected to {host_string} in {:?}", start.elapsed());
    let mut send_stream = connection.open_uni().await.map_err(|e| anyhow!("failed to open stream: {}", e))?;

    // Simulate NAT rebinding after connecting
    if options.rebind {
        let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
        let addr = socket.local_addr().unwrap();
        println!("rebinding to {addr}");
        server_endpoint.rebind(socket).expect("rebind failed");
    }

    // Send the GET request to the server
    let request = format!("GET {}\r\n", options.url.path());
    send_stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| anyhow!("failed to send request: {}", e))?;
    send_stream
        .finish()
        .await
        .map_err(|e| anyhow!("failed to shutdown stream: {}", e))?;
    let response_start = Instant::now();
    println!("Request sent at {:?}", response_start - start);

    // Wait for the server to dial us using a uni-directional stream
    let mut receive_stream = connection
        .accept_uni()
        .await
        .map_err(|e| anyhow!("failed to accept stream: {}", e))?;

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

    if resp.starts_with(b"This contains some text, my friend") {
        println!("The file response is valid!!")
    } else {
        panic!("Unexpected response!!")
    }

    // Close the connection
    connection.close(0u32.into(), b"done");

    // Give the server a fair chance to receive the close packet
    server_endpoint.wait_idle().await;

    Ok(())
}

/// Returns the default server configuration along with its dummy certificate
fn configure_server() -> io::Result<(ServerConfig, Vec<u8>)> {
    // Create the dummy server certificate
    let cert = rcgen::generate_simple_self_signed(vec![SERVER_STRING.into()]).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let priv_key = cert.serialize_private_key_der();
    let priv_key = rustls::PrivateKey(priv_key);
    let cert_chain = vec![rustls::Certificate(cert_der.clone())];

    // Create the server transport config
    let transport_config = create_transport_config();

    // Create the QUIC server configuration
    let mut server_config =
        ServerConfig::with_single_cert(cert_chain, priv_key).map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Invalid server certificate: {:?}", error),
            )
        })?;
    server_config.transport_config(transport_config);

    Ok((server_config, cert_der))
}

fn duration_secs(x: &Duration) -> f32 {
    x.as_secs() as f32 + x.subsec_nanos() as f32 * 1e-9
}

struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

/// Returns the default client configured that ignores the server certificate
fn configure_client() -> ClientConfig {
    // Create the dummy crypto config
    let crypto_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    // Create the client transport config
    let transport_config = create_transport_config();

    // Create the QUIC client configuration
    let mut client = ClientConfig::new(Arc::new(crypto_config));
    client.transport_config(transport_config);
    client
}

/// Returns a new transport config
fn create_transport_config() -> Arc<TransportConfig> {
    let mut transport_config = quinn::TransportConfig::default();

    transport_config.max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(20_000)))); // 20 secs
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(20))); // 20 secs

    Arc::new(transport_config)
}
