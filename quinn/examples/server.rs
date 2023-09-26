//! This example demonstrates an HTTP server that serves files from a directory.
//!
//! Checkout the `README.md` for guidance.

use std::{
    ascii, fs, io,
    net::SocketAddr,
    path::{self, Path, PathBuf},
    str,
    sync::Arc,
};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use rustls::{Certificate, PrivateKey};
use tracing::{error};

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
    // Gather the certificate and private key
    let (certificates, private_key) = gather_certificates_and_private_key(&options)?;

    // Create the crypto server config using the root certificates and specified options
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;
    server_crypto.alpn_protocols = common::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    if options.keylog {
        server_crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    // Create the QUIC server config
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    if options.stateless_retry {
        server_config.use_retry(true);
    }

    // Create the transport config
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into()); // WHY??

    // Get the root filepath to serve the files from
    let root_filepath = Arc::<Path>::from(options.root.clone());
    if !root_filepath.exists() {
        bail!("root filepath does not exist");
    }

    // Create the server endpoint
    let endpoint = quinn::Endpoint::server(server_config, options.listen)?;
    println!("Server listening on {}", endpoint.local_addr()?);

    // Accept incoming connections
    while let Some(incoming_connection) = endpoint.accept().await {
        println!("Got connection! Connection remote: {:?}", incoming_connection.remote_address());
        let handle_connection_future = handle_connection(root_filepath.clone(), incoming_connection);
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
    println!("Certificate path: {:?} and key path: {:?}", cert_path, key_path);
    let (cert, key) = match fs::read(&cert_path).and_then(|x| Ok((x, fs::read(&key_path)?))) {
        Ok(x) => x,
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            println!("generating self-signed certificate");
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
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

async fn handle_connection(root_filepath: Arc<Path>, incoming_connection: quinn::Connecting) -> Result<()> {
    let connection = incoming_connection.await?;
    println!(
        "Got connection! Remote: {:?}, Protocol: {:?}",
        connection.remote_address(),
        connection
            .handshake_data()
            .unwrap()
            .downcast::<quinn::crypto::rustls::HandshakeData>().unwrap()
            .protocol
            .map_or_else(|| "<none>".into(), |x| String::from_utf8_lossy(&x).into_owned())
    );
    async {
        println!("established");

        // Each stream initiated by the client constitutes a new request.
        loop {
            let stream = connection.accept_bi().await;
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    println!("connection closed");
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(s) => s,
            };
            let handle_request_future = handle_request(root_filepath.clone(), stream);
            tokio::spawn(
                async move {
                    if let Err(e) = handle_request_future.await {
                        error!("Request failed: {reason}", reason = e.to_string());
                    }
                }
            );
        }
    }
    .await?;
    Ok(())
}

async fn handle_request(
    root_filepath: Arc<Path>,
    (mut send_stream, mut receive_stream): (quinn::SendStream, quinn::RecvStream),
) -> Result<()> {
    // Get the request
    let req = receive_stream
        .read_to_end(64 * 1024)
        .await
        .map_err(|e| anyhow!("failed reading request: {}", e))?;

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

    // Write the response
    send_stream.write_all(&resp)
        .await
        .map_err(|e| anyhow!("failed to send response: {}", e))?;

    // Gracefully terminate the stream
    send_stream.finish()
        .await
        .map_err(|e| anyhow!("failed to shutdown stream: {}", e))?;
    println!("complete");

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
    let end = request_path_bytes.iter().position(|&c| c == b' ').unwrap_or(request_path_bytes.len());
    let request_path_string = str::from_utf8(&request_path_bytes[..end]).context("path is malformed UTF-8")?;
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
