use std::net::{SocketAddr, TcpListener};

use std::io;
use structopt::StructOpt;
use tracing::info;

#[derive(StructOpt, Debug)]
struct Cmd {
    /// Address to listen on for inbound packets
    /// defaults to port 5000
    #[structopt(long, default_value = "0.0.0.0:5000")]
    addr: SocketAddr,
    #[structopt(long)]
    disable_rules: bool,
}

#[tracing::instrument]
fn main() -> Result<(), io::Error> {
    tracing_subscriber::fmt::init();
    let Cmd {
        addr,
        disable_rules,
    } = Cmd::from_args();

    if !disable_rules {
        // do nothing for now
    }

    let socket = TcpListener::bind(addr)?;

    Ok(())
}
