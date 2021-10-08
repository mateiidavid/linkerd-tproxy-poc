use std::io::{self, prelude::*};
use std::net::TcpListener;
use tracing::info;

#[tracing::instrument]
fn main() -> io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:80")?;
    info!("Listening on :80");
    loop {
        let (mut stream, accept) = listener.accept()?;
        info!(%accept, "Handling client");
        let mut buf = [0u8; 2048];
        let n = stream.read(&mut buf[..])?;
        if n == 0 {
            break;
        }
        let what_was_said = std::str::from_utf8(&buf).unwrap();
        info!(%what_was_said, bytz = %n, "Read some bytz");
        stream.write(b"Hallo")?;
    }
    Ok(())
}
