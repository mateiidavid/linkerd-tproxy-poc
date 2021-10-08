use std::net::{SocketAddr, TcpListener};

use socket2::{Domain, Socket, Type};
use std::io::{self, prelude::*};
use std::process::{Command, Output};
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

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

// Using tokio mostly for the `net` feature
// don't want to set socket opts using "unsafe"
#[tracing::instrument]
fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    info!("HALLO");
    println!("HALLO)O");
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
        socket.bind(&addr.into())?;
        socket.listen(10)?;
        socket.into()
    };

    loop {
        match listener.accept() {
            Ok((_stream, accept)) => {
                info!(%accept, "Handling connection");
                //stream.write(b"Hello")?;
                break;
            }
            Err(e) => {
                info!(?e, "Error on conn accept");
                panic!("for now just panic");
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
    info!("Adding redirect rule; from dport 80 to 5000");
    let tproxy = Command::new("iptables")
        .args([
            "-t",
            "mangle",
            "-A",
            "PREROUTING",
            "-p",
            "tcp",
            "--dport",
            "80",
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
    //ipt.append(table, chain, rule);

    /*
         * assert!(ipt.new_chain("nat", "NEWCHAINNAME").is_ok());
    assert!(ipt.append("nat", "NEWCHAINNAME", "-j ACCEPT").is_ok());
    assert!(ipt.exists("nat", "NEWCHAINNAME", "-j ACCEPT").unwrap());
    assert!(ipt.delete("nat", "NEWCHAINNAME", "-j ACCEPT").is_ok());
    assert!(ipt.delete_chain("nat", "NEWCHAINNAME").is_ok());
    */

    /*
         * # iptables -t mangle -N DIVERT
    # iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
    # iptables -t mangle -A DIVERT -j MARK --set-mark 1
    # iptables -t mangle -A DIVERT -j ACCEPT
         */

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
