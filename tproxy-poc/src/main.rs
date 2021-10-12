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

#[tracing::instrument]
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
// Using tokio mostly for the `net` feature
// don't want to set socket opts using "unsafe"
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
                info!(client = %accept, "Read {} bytes", sz);
                let bind_addr = SocketAddr::new(accept.ip(), 0);
                let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3000);
                tokio::spawn(async move {
                    let remote = mk_redirect_socket(&bind_addr.into(), &remote_addr.into());
                    if let Ok(mut stream) = remote {
                        let mut buf = [0u8; 2048];
                        let local_addr = stream.local_addr().expect("failed to read local addr");
                        let remote_addr = stream.peer_addr().expect("failed to read peer addr");
                        info!(%local_addr, "Connected to {}", remote_addr);
                        let sz = stream.write(&buf[..sz]).expect("failed to write");
                        info!(%remote_addr, %local_addr, "Wrote {} bytes", sz);
                        stream.read(&mut buf[..]).expect("failed to read");
                        info!(%remote_addr, %local_addr, "Read {} bytes", sz);
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
    info!("Setting up");
    let ipt = iptables::new(false)?;
    let table = "mangle";
    let chains = ipt.list_chains(table)?;
    info!(?chains, "Current chains");
    let chain = "DIVERT_TEST";
    let divert_rules = ["-j MARK --set-mark 1", "-j ACCEPT"];
    if !ipt.chain_exists(table, chain)? {
        info!(%chain, "Creating inexistent chain");
        ipt.new_chain(table, chain)?;
    }
    // Add DIVERT jump
    ipt.append(table, "PREROUTING", "-p tcp -m socket -j DIVERT_TEST")?;

    for rule in divert_rules {
        info!(?table, ?chain, ?rule, "adding divert rule");
        ipt.append(table, chain, rule)?;
    }
    info!("Configuring route table");
    let _ = {
        let (fwmark, route) = route_table();
        let fwmark = fwmark.expect("failed to execute rule add fwmark");
        let route = route.expect("failed to execute route add local");
        info!(?route, ?fwmark, "ip table rules");
    };

    // iptables -t mangle -A PREROUTING -p tcp --dport 80 -j TPROXY --tproxy-mark 0x1/0x1 --on-port 50080
    info!("Adding redirect rule; from dport 3000 to 5000");
    exec_cmd(
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
    )
    .expect("could not exec conn_mark preroute save mark");

    exec_cmd(
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
    )
    .expect("could not exec conn_mark preroute save mark");
    exec_cmd(
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
    )
    .expect("could not exec conn_mark output restore mark");

    exec_cmd(
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
    )
    .unwrap();
    let tproxy = Command::new("iptables")
        .args([
            "-t",
            "mangle",
            "-A",
            "PREROUTING",
            "-p",
            "tcp",
            "--dport",
            "3000",
            "!",
            "-d",
            "127.0.0.1/32",
            "-j",
            "TPROXY",
            "--tproxy-mark",
            "0x1/0x1",
            "--on-port",
            "5000",
        ])
        .output()
        .expect("failed to set up tproxy");
    io::stdout().write_all(&tproxy.stdout).unwrap();

    let saved = Command::new("iptables-legacy")
        .args(["-t", "mangle", "-L"])
        .output()
        .expect("failed to list rules");
    io::stdout().write_all(&saved.stdout).unwrap();
    let routes = Command::new("ip")
        .args(["route", "show", "table", "all"])
        .output()
        .expect("failed to list rules");
    io::stdout().write_all(&routes.stdout).unwrap();

    exec_cmd("sysctl", ["-w", "net/ipv4/conf/eth0/route_localnet=1"]).unwrap();
    exec_cmd("sysctl", ["net/ipv4/conf/eth0/route_localnet"]).unwrap();
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

fn exec_cmd<I, S>(cmd: &str, args: I) -> io::Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let cmd = Command::new(cmd)
        .args(args)
        .output()
        .expect("failed to set up connmark save");
    io::stdout().write_all(&cmd.stdout)
}
