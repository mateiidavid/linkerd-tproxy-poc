use std::net::{SocketAddr, TcpListener};

use socket2::{Domain, Socket, Type};
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

// Using tokio mostly for the `net` feature
// don't want to set socket opts using "unsafe"
#[tracing::instrument]
fn main() -> io::Result<()> {
    tracing_subscriber::fmt::init();
    let Cmd {
        addr,
        disable_rules,
    } = Cmd::from_args();

    if !disable_rules {
        // do nothing for now
    }

    let listener: TcpListener = {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(socket2::Protocol::TCP))?;
        // Set IP_TRANSPARENT sock opt, requires CAP_ADMIN_NET
        // IP_TRANSPARENT is mandatory for TPROXY
        socket.set_ip_transparent(true)?;
        socket.bind(&addr.into())?;
        socket.listen(10)?;
        socket.into()
    };

    for stream in listener.incoming() {
        info!("Connected")
    }

    Ok(())
}
