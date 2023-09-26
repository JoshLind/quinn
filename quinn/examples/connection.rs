//! This example intends to use the smallest amount of code to make a simple QUIC connection.
//!
//! Checkout the `README.md` for guidance.

mod common;
use common::{make_client_endpoint, make_server_endpoint};
use quinn::Endpoint;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure the server endpoint
    let server_addr = "127.0.0.1:5000".parse().unwrap();
    let (server_endpoint, server_certificate) = make_server_endpoint(server_addr)?;

    // Spawn a server that accepts connections
    spawn_server(server_endpoint);

    // Configure the client endpoint
    let bind_addr = "0.0.0.0:0".parse().unwrap();
    let client_endpoint = make_client_endpoint(bind_addr, &[&server_certificate])?;

    // Connect to the server several times
    for _ in 0..3 {
        let connection = client_endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        println!(
            "[CLIENT] Connect to server! Connection address: {:?}, connection: {:?}",
            connection.remote_address(),
            connection
        );

        // Waiting for a stream will complete with an error when the server closes the connection
        let _ = connection.accept_uni().await;

        // Make sure the server has a chance to clean up
        client_endpoint.wait_idle().await;

        println!("---")
    }

    Ok(())
}

/// Spawns a simple server using the given endpoint. The server
/// accepts a connection and then drops it.
fn spawn_server(endpoint: Endpoint) {
    tokio::spawn(async move {
        loop {
            let icnoming_connection = endpoint.accept().await.unwrap();
            let connection = icnoming_connection.await.unwrap();

            println!(
                "[SERVER] Got connection from client! Connection address: {:?}, connection: {:?}",
                connection.remote_address(),
                connection
            );
            // Dropping all handles associated with a connection implicitly closes it
        }
    });
}
