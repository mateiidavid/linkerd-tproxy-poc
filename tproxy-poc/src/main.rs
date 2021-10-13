use std::ffi::OsStr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};

use socket2::{Domain, Socket, Type};
use std::io::{self, prelude::*};
use std::process::{Command, Output};
use structopt::StructOpt;
use tracing::{error, info};

#[derive(StructOpt, Debug)]
struct Cmd {
    /// Address to listen on for inbound packets
    /// defaults to port 5000
    #[structopt(long, default_value = "0.0.0.0:5000")]
    addr: SocketAddr,
    #[structopt(long)]
    disable_rules: bool,
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn mk_redirect_socket(
    src_addr: &socket2::SockAddr,
    dst_addr: &socket2::SockAddr,
) -> io::Result<TcpStream> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(socket2::Protocol::TCP))?;
    // Set IP_TRANSPARENT sock opt, requires CAP_ADMIN_NET
    // IP_TRANSPARENT is mandatory for TPROXY
    socket.set_reuse_address(true)?;
    socket.set_freebind(true)?;
    socket.set_ip_transparent(true)?;
    socket.set_mark(1)?;
    let opts = (socket.ip_transparent()?, socket.freebind()?, socket.mark()?);
    info!(is_transparent = %opts.0, is_freebind = %opts.1, sock_mark = %opts.2, "Making redirect client socket");
    socket.bind(src_addr)?;
    socket.connect(dst_addr)?;
    Ok(TcpStream::from(socket))
}

#[tracing::instrument]
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let Cmd {
        addr,
        disable_rules,
    } = Cmd::from_args();
    if !disable_rules {
        info!("Setting up iptables");
        init_iptables()?;
    }

    let listener: TcpListener = {
        info!("Setting up listener");
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(socket2::Protocol::TCP))?;
        // Set IP_TRANSPARENT sock opt, requires CAP_ADMIN_NET
        // IP_TRANSPARENT is mandatory for TPROXY
        socket.set_ip_transparent(true)?;
        socket.set_reuse_address(true)?;
        socket.bind(&addr.into())?;
        socket.listen(10)?;
        socket.into()
    };

    loop {
        // spawn here, check for looping to make sure ...
        match listener.accept() {
            Ok((mut accept_stream, accept)) => {
                let local_addr = accept_stream.local_addr()?;
                info!(%accept, server = %local_addr, "Handling connection");
                let mut buf = [0u8; 2048];
                let sz = accept_stream.read(&mut buf[..])?;
                info!(client = %accept, "Read {} bytes from client", sz);
                let bind_addr = SocketAddr::new(accept.ip(), 0);
                let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3000);
                tokio::spawn(async move {
                    let remote = mk_redirect_socket(&bind_addr.into(), &remote_addr.into());
                    if let Ok(mut stream) = remote {
                        let local_addr = stream.local_addr().expect("failed to read local addr");
                        let remote_addr = stream.peer_addr().expect("failed to read peer addr");
                        info!(%local_addr, "Connected to {}", remote_addr);
                        stream
                            .write(b"Hello, this is redirect speaking")
                            .expect("failed to write");
                        info!(%remote_addr, %local_addr, "Wrote {} bytes to server", sz);
                        let mut buf = [0u8; 2048];
                        let sz = stream.read(&mut buf[..]).expect("failed to read");
                        let read = std::str::from_utf8(&buf[..sz]).unwrap();
                        info!(%remote_addr, %local_addr, "Read {} bytes from server: {}", sz, read);
                    } else if let Err(e) = remote {
                        error!(error = %e, spoofed_client = %accept, %remote_addr, "failed to connect to server");
                        //break;
                    }
                });
            }
            Err(e) => {
                info!(?e, "Error on conn accept");
                break;
            }
        }
    }

    Ok(())
}

#[tracing::instrument]
fn init_iptables() -> Result<()> {
    info!("Setting up iptables");
    // IPTables bindings. Unfortunately, doesn't seem to play well with TPROXY
    // module, so it's only being used to set up the initial rules and chains.
    // This is mostly for marking packets and accepting connections on the
    // DIVERT_TEST chain. The false here means we are NOT using IPV6.
    let ipt = iptables::new(false)?;
    let chains = ipt.list_chains("mangle")?;
    info!(?chains, "Current chains");
    if !ipt.chain_exists("mangle", "DIVERT_TEST")? {
        info!("Creating inexistent chain DIVERT_TEST");
        ipt.new_chain("mangle", "DIVERT_TEST")?;
    }
    // Add DIVERT jump
    ipt.append("mangle", "PREROUTING", "-p tcp -m socket -j DIVERT_TEST")?;
    ipt.append("mangle", "DIVERT_TEST", "-j MARK --set-mark 1")?;
    ipt.append("mangle", "DIVERT_TEST", "-j ACCEPT")?;
    info!("Configuring route table");
    let _ = {
        let (fwmark, route) = route_table();
        let fwmark = fwmark.expect("failed to execute rule add fwmark");
        let route = route.expect("failed to execute route add local");
        info!(?route, ?fwmark, "ip table rules");
    };

    // ++++++++++++++++
    // + TPROXY RULES +
    // ++++++++++++++++
    // * 
    info!("Adding redirect rule; from dport 3000 to 5000");
    exec(
        "iptables",
        [
            "-t",
            "mangle",
            "-I",
            "PREROUTING",
            "-m",
            "mark",
            "--mark",
            "1",
            "-j",
            "CONNMARK",
            "--save-mark",
        ],
    )?;

    exec(
        "iptables",
        [
            "-t",
            "mangle",
            "-I",
            "OUTPUT",
            "-s",
            "127.0.0.1/32",
            "!",
            "-d",
            "127.0.0.1/32",
            "-j",
            "MARK",
            "--set-xmark",
            "1",
        ],
    )?;

    exec(
        "iptables",
        [
            "-t",
            "mangle",
            "-A",
            "OUTPUT",
            "-m",
            "connmark",
            "--mark",
            "1",
            "-j",
            "CONNMARK",
            "--restore-mark",
        ],
    )?;

    exec(
        "iptables",
        [
            "-t",
            "mangle",
            "-A",
            "DIVERT_TEST",
            "-m",
            "conntrack",
            "--ctstate",
            "RELATED,ESTABLISHED",
            "-j",
            "RETURN",
        ],
    )?;
    // TPROXY rule
    exec(
        "iptables",
        [
            "-t",
            "mangle",
            "-A",
            "PREROUTING",
            "-p",
            "tcp",
            "!",
            "-d",
            "127.0.0.1/32",
            "-j",
            "TPROXY",
            "--tproxy-mark",
            "0x1/0x1",
            "--on-port",
            "5000",
        ],
    )?;

    // Show saved iptables state and routes
    exec("iptables-legacy", ["-t", "mangle", "-L"])?;
    // Route table 100 constructed for packets that are marked
    exec("ip", ["route", "show", "table", "100"])?;

    exec("sysctl", ["-w", "net/ipv4/conf/eth0/route_localnet=1"])?;
    Ok(())
}

// Configure routing table (explain)
fn route_table() -> (
    std::result::Result<Output, io::Error>,
    std::result::Result<Output, io::Error>,
) {
    // TODO: Explain
    let add_fwmark = Command::new("ip")
        .args(["rule", "add", "fwmark", "1", "lookup", "100"])
        .output();

    // TODO: explain
    let add_route = Command::new("ip")
        .args([
            "route",
            "add",
            "local",
            "0.0.0.0/0",
            "dev",
            "lo",
            "table",
            "100",
        ])
        .output();
    (add_fwmark, add_route)
}

fn exec<I, S>(cmd: &str, args: I) -> io::Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let cmd = Command::new(cmd)
        .args(args)
        .output()
        .expect(&format!("failed to exec {}", cmd));
    io::stdout().write_all(&cmd.stdout)
}
