use std::io::{self, prelude::*};
#[warn(unreachable_code)]
use std::net::TcpListener;

use tracing::info;

fn main() -> io::Result<()> {
    tracing_subscriber::fmt::init();
    let listener = TcpListener::bind("0.0.0.0:3000")?;
    info!("Listening on :3000");
    loop {
        info!("Accepting");
        let (mut stream, accept) = listener.accept()?;
        let srv = stream.local_addr()?;
        info!(%srv, %accept, "Connection accepted");
        let mut buf = [0u8; 2048];
        match stream.read(&mut buf[..]) {
            Ok(0) => {
                info!("Received 0 bytes, closing");
                break;
            }
            Ok(sz) => {
                let data = std::str::from_utf8(&buf[..sz]).unwrap();
                info!("Read {} bytes: {}", sz, data);
                let sz = stream.write(b"Well, hello!")?;
                info!("Wrote {} bytes", sz);
            }
            Err(e) => {
                info!(err = ?e, "error on read");
                break;
            }
        }
    }

    Ok(())
}
