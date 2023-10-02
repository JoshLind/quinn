//! This example demonstrates an HTTP server that serves files from a directory.
//!
//! Checkout the `README.md` for guidance.

use std::net::IpAddr;
use std::{
    ascii, fs, io,
    net::SocketAddr,
    path::{self, Path, PathBuf},
    str,
    sync::Arc,
};

use crate::common::SERVER_STRING;
use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use proto::{ClientConfig, IdleTimeout, ServerConfig, TransportConfig, VarInt};
use rustls::{Certificate, PrivateKey};
use tracing::error;

mod common;

#[derive(Parser, Debug)]
#[clap(name = "server")]
struct Opt {
    /// file to log TLS keys to for debugging
    #[clap(long = "keylog")]
    keylog: bool,
    /// directory to serve files from
    root: PathBuf,
    /// TLS private key in PEM format
    #[clap(short = 'k', long = "key", requires = "cert")]
    key: Option<PathBuf>,
    /// TLS certificate in PEM format
    #[clap(short = 'c', long = "cert", requires = "key")]
    cert: Option<PathBuf>,
    /// Enable stateless retries
    #[clap(long = "stateless-retry")]
    stateless_retry: bool,
    /// Address to listen on
    #[clap(long = "listen", default_value = "[::1]:4433")]
    listen: SocketAddr,
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
    // Get the root filepath to serve the files from
    let root_filepath = Arc::<Path>::from(options.root.clone());
    if !root_filepath.exists() {
        bail!("root filepath does not exist");
    }

    // Create the QUIC server configuration
    let (server_config, _server_certificate) = configure_server()?;

    // Create the QUIC server endpoint
    let socket_addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 61616);
    let mut server_endpoint = quinn::Endpoint::server(server_config, socket_addr)?;
    server_endpoint.set_default_client_config(configure_client()); // Required to skip certificate verification
    println!("Server listening on {}", server_endpoint.local_addr()?);

    // Accept incoming connections
    while let Some(incoming_connection) = server_endpoint.accept().await {
        println!(
            "Got connection! Connection remote: {:?}",
            incoming_connection.remote_address()
        );
        let handle_connection_future =
            handle_connection(root_filepath.clone(), incoming_connection);
        tokio::spawn(async move {
            if let Err(e) = handle_connection_future.await {
                error!("connection failed: {reason}", reason = e.to_string())
            }
        });
    }

    Ok(())
}

/// Gathers the certificates for the server and the private keys
fn gather_certificates_and_private_key(options: &Opt) -> Result<(Vec<Certificate>, PrivateKey)> {
    // If the user specified a certificate and a private key, use them
    if let (Some(key_path), Some(cert_path)) = (&options.key, &options.cert) {
        println!("using provided certificate and private key");
        let key = fs::read(key_path).context("failed to read private key")?;
        let key = if key_path.extension().map_or(false, |x| x == "der") {
            rustls::PrivateKey(key)
        } else {
            let pkcs8 = rustls_pemfile::pkcs8_private_keys(&mut &*key)
                .context("malformed PKCS #8 private key")?;
            match pkcs8.into_iter().next() {
                Some(x) => rustls::PrivateKey(x),
                None => {
                    let rsa = rustls_pemfile::rsa_private_keys(&mut &*key)
                        .context("malformed PKCS #1 private key")?;
                    match rsa.into_iter().next() {
                        Some(x) => rustls::PrivateKey(x),
                        None => {
                            anyhow::bail!("no private keys found");
                        }
                    }
                }
            }
        };
        let cert_chain = fs::read(cert_path).context("failed to read certificate chain")?;
        let cert_chain = if cert_path.extension().map_or(false, |x| x == "der") {
            vec![rustls::Certificate(cert_chain)]
        } else {
            rustls_pemfile::certs(&mut &*cert_chain)
                .context("invalid PEM-encoded certificate")?
                .into_iter()
                .map(rustls::Certificate)
                .collect()
        };

        return Ok((cert_chain, key));
    }

    // Otherwise, determine the paths and generate a self-signed certificate (if required)
    let dirs = directories_next::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
    let path = dirs.data_local_dir();
    let cert_path = path.join("cert.der");
    let key_path = path.join("key.der");
    println!(
        "Certificate path: {:?} and key path: {:?}",
        cert_path, key_path
    );
    let (cert, key) = match fs::read(&cert_path).and_then(|x| Ok((x, fs::read(&key_path)?))) {
        Ok(x) => x,
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            println!("generating self-signed certificate");
            let cert =
                rcgen::generate_simple_self_signed(vec![SERVER_STRING.into()]).unwrap();
            let key = cert.serialize_private_key_der();
            let cert = cert.serialize_der().unwrap();
            fs::create_dir_all(path).context("failed to create certificate directory")?;
            fs::write(&cert_path, &cert).context("failed to write certificate")?;
            fs::write(&key_path, &key).context("failed to write private key")?;
            (cert, key)
        }
        Err(e) => {
            bail!("failed to read certificate: {}", e);
        }
    };

    Ok((vec![Certificate(cert)], PrivateKey(key)))
}

async fn handle_connection(
    root_filepath: Arc<Path>,
    incoming_connection: quinn::Connecting,
) -> Result<()> {
    let connection = incoming_connection.await?;
    println!(
        "Got connection! Remote: {:?}, Protocol: {:?}",
        connection.remote_address(),
        connection
            .handshake_data()
            .unwrap()
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .unwrap()
            .protocol
            .map_or_else(
                || "<none>".into(),
                |x| String::from_utf8_lossy(&x).into_owned()
            )
    );
    async {
        println!("established");

        // Each stream initiated by the client constitutes a new request.
        loop {
            // Accept the request via a uni-directional channel
            let receive_stream = connection.accept_uni().await;
            let mut receive_stream = match receive_stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    println!("connection closed");
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(s) => s,
            };

            // Get the request
            let req = receive_stream
                .read_to_end(64 * 1024)
                .await
                .map_err(|e| anyhow!("failed reading request: {}", e)).unwrap();

            // Print the request
            let mut escaped = String::new();
            for &char in &req[..] {
                let part = ascii::escape_default(char).collect::<Vec<_>>();
                escaped.push_str(str::from_utf8(&part).unwrap());
            }
            println!("Got request : {}", escaped);

            // Execute the request
            let resp = process_get(&root_filepath, &req).unwrap_or_else(|e| {
                error!("failed: {}", e);
                format!("failed to process request: {e}\n").into_bytes()
            });

            // Open a uni-directional channel to send the response
            let mut send_stream = connection
                .open_uni()
                .await
                .map_err(|e| anyhow!("failed to open stream: {}", e)).unwrap();

            // Write the response
            send_stream
                .write_all(&resp)
                .await
                .map_err(|e| anyhow!("failed to send response: {}", e)).unwrap();

            // Gracefully terminate the stream
            send_stream
                .finish()
                .await
                .map_err(|e| anyhow!("failed to shutdown stream: {}", e)).unwrap();
            println!("complete");
        }
    }
    .await?;
    Ok(())
}

fn process_get(root_filepath: &Path, request: &[u8]) -> Result<Vec<u8>> {
    // Verify the request starts with "GET "
    if request.len() < 4 || &request[0..4] != b"GET " {
        bail!("missing GET");
    }

    // Verify the request specifies a path
    if request[4..].len() < 2 || &request[request.len() - 2..] != b"\r\n" {
        bail!("missing \\r\\n");
    }

    // Construct the request_path
    let request_path_bytes = &request[4..request.len() - 2];
    let end = request_path_bytes
        .iter()
        .position(|&c| c == b' ')
        .unwrap_or(request_path_bytes.len());
    let request_path_string =
        str::from_utf8(&request_path_bytes[..end]).context("path is malformed UTF-8")?;
    let request_path = Path::new(&request_path_string);

    // Identify the absolute file path
    let mut real_path = PathBuf::from(root_filepath);
    let mut components = request_path.components();
    match components.next() {
        Some(path::Component::RootDir) => {}
        _ => {
            bail!("path must be absolute");
        }
    }

    // Verify that the path components exist
    for component in components {
        match component {
            path::Component::Normal(x) => {
                real_path.push(x);
            }
            x => {
                bail!("illegal component in path: {:?}", x);
            }
        }
    }

    // Read the file and return the data
    let data = fs::read(&real_path).context("failed reading file")?;
    Ok(data)
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
