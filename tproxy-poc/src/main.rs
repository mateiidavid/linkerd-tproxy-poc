use std::ffi::OsStr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::str::FromStr;

use socket2::{Domain, Socket, Type};
use std::io::{self, prelude::*};
use std::process::{Command, Output};
use structopt::StructOpt;
use tracing::{error, info};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(StructOpt, Debug)]
struct Cmd {
    /// Address to listen on for inbound packets
    /// defaults to port 5000
    #[structopt(long, default_value = "0.0.0.0:5000")]
    addr: SocketAddr,
    #[structopt(long)]
    mode: Option<InterceptMode>,
}

#[derive(Debug)]
enum InterceptMode {
    Tproxy(),
    Nat(),
}

impl FromStr for InterceptMode {
    type Err = &'static str;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_ref() {
            "tproxy" => Ok(InterceptMode::Tproxy()),
            "nat" => Ok(InterceptMode::Nat()),
            _ => Err("intercept mode not supported"),
        }
    }
}

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
    let Cmd { addr, mode } = Cmd::from_args();
    let mode = if let Some(m) = mode {
        match m {
            InterceptMode::Tproxy() => {
                info!("Using Tproxy rules for iptables");
                init_iptables(m)?;
                "tproxy"
            }
            InterceptMode::Nat() => {
                info!("Using NAT rules for iptables");
                init_iptables(m)?;
                "nat"
            }
        }
    } else {
        panic!("No interception mode set!");
    };

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
                let remote_addr = if mode == "tproxy" {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3000)
                } else {
                    // socket2 doesn't have any functions to get SO_ORIGINAL_DST
                    // from the socket, so we hardcode the local_addr and port
                    // to send to app. We know ahead of time it will share the
                    // same IP and listen on port 3000.
                    SocketAddr::new(local_addr.ip(), 3000)
                };
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
fn init_iptables(mode: InterceptMode) -> Result<()> {
    info!("Setting up iptables");
    // IPTables bindings. Unfortunately, doesn't seem to play well with TPROXY
    // module, so it's only being used to set up the initial rules and chains.
    // This is mostly for marking packets and accepting connections on the
    // DIVERT_TEST chain. The false here means we are NOT using IPV6.
    let ipt = iptables::new(false)?;
    match mode {
        InterceptMode::Tproxy() => {
            let chains = ipt.list_chains("mangle")?;
            info!(?chains, "Current state for mangle");
            if !ipt.chain_exists("mangle", "DIVERT_TEST")? {
                info!("Creating inexistent chain DIVERT_TEST");
                ipt.new_chain("mangle", "DIVERT_TEST")?;
            }
            // Add DIVERT jump
            ipt.append("mangle", "PREROUTING", "-p tcp -m socket -j DIVERT_TEST")?;
            ipt.append("mangle", "DIVERT_TEST", "-j MARK --set-mark 1")?;
            ipt.append("mangle", "DIVERT_TEST", "-j ACCEPT")?;
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
        }
        InterceptMode::Nat() => {
            let chains = ipt.list_chains("nat")?;
            info!(?chains, "Current state for nat");
            if !ipt.chain_exists("nat", "INIT_REDIRECT")? {
                info!("Creating inexistent chain INIT_REDIRECT");
                ipt.new_chain("nat", "INIT_REDIRECT")?;
            }
            ipt.append("nat", "INIT_REDIRECT", "-p tcp -j REDIRECT --to-port 5000")?;
            ipt.append("nat", "PREROUTING", "-j INIT_REDIRECT")?;
        }
    }

    info!("Configuring route table");
    let _ = {
        let (fwmark, route) = route_table();
        let fwmark = fwmark.expect("failed to execute rule add fwmark");
        let route = route.expect("failed to execute route add local");
        info!(?route, ?fwmark, "ip table rules");
    };

    // ++++++++++++++++++
    // + CONNMARK RULES +
    // ++++++++++++++++++
    // *
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
