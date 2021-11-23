use std::ffi::OsStr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use socket2::{Domain, Socket, Type};
use std::io::{self, prelude::*};
use std::process::{Command, Output};
use structopt::StructOpt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(StructOpt, Debug)]
struct Cmd {
    /// Address to listen on for inbound packets
    /// defaults to port 5000
    #[structopt(long, default_value = "0.0.0.0:5000")]
    addr: SocketAddr,
    /// Intercept mode for tproxy poc. It can either be 'nat' or 'tproxy';
    /// different modes will set up iptables differently, client IP will still
    /// be spoofed.
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

// Creates socket used to connect from proxy to application process. It takes in
// a src address to bind to, and the dst address to connect to.
fn mk_redirect_socket(
    src_addr: &socket2::SockAddr,
    dst_addr: &socket2::SockAddr,
) -> io::Result<TcpStream> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(socket2::Protocol::TCP))?;
    // Set IP_TRANSPARENT sock opt, requires CAP_ADMIN_NET. IP_TRANSPARENT as a
    // socket option here allows us to bind to a non-local address; without it,
    // we wouldn't be able to bind to the client address.
    socket.set_reuse_address(true)?;
    socket.set_freebind(true)?;
    socket.set_ip_transparent(true)?;
    // We also mark the packet with the mark that we configured for tproxy and
    // (or) CONNMARK (more below). This ensures that the packet will be routed
    // correctly, according to our routing policy.
    socket.set_mark(1)?;
    let opts = (socket.ip_transparent()?, socket.freebind()?, socket.mark()?);
    info!(is_transparent = %opts.0, is_freebind = %opts.1, sock_mark = %opts.2, "Making redirect client socket");

    // connect-before-bind: behavior undefined
    // bind-before-connect: for a client ip misdirect
    socket.bind(src_addr)?;
    socket.connect(dst_addr)?;
    let stream = std::net::TcpStream::from(socket);
    Ok(TcpStream::from_std(stream)?)
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

    // Set-up listener. If we are running in 'tproxy' mode, then we set an
    // additional option on the socket: IP_TRANSPARENT. It requires
    // CAP_ADMIN_NET and it works together with the tproxy iptables module. The
    // socket option itself lets us bind to a non-local address, in this case it
    // allows us to receive traffic routed through the tproxy ipt target.
    let listener: TcpListener = {
        info!("Setting up listener");
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(socket2::Protocol::TCP))?;
        if mode == "tproxy" {
            socket.set_ip_transparent(true)?;
        };
        socket.set_reuse_address(true)?;
        socket.bind(&addr.into())?;
        socket.listen(10)?;
        // sock2 does not have any traits to convert from a socket to an async
        // tcp listener. Instead, we convert the socket into a sync listener and
        // create tokio async listener from that.
        TcpListener::from_std(socket.into())?
    };

    loop {
        match listener.accept() {
            Ok((mut accept_stream, accept)) => {
                let local_addr = accept_stream.local_addr()?;
                info!(%accept, server = %local_addr, "Handling connection");

                let mut buf = [0u8; 2048];
                let sz = accept_stream.read(&mut buf[..])?;
                info!(client = %accept, "Read {} bytes from client", sz);

                // We need to create a new connection from the proxy to the
                // application process. We will bind to the src IP of the client
                // before we connect; the remote address will be either
                // localhost: 3000 (if we are in tproxy mode) or podIP:3000.
                // We can still use original address with tproxy, but it
                // requires additional ipt rules.
                let bind_addr = accept.clone();
                let remote_addr = if mode == "tproxy" {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3000)
                } else {
                    // socket2 doesn't have any functions to get SO_ORIGINAL_DST
                    // from the socket, so we hardcode the local_addr and port
                    // to send to app. We know ahead of time it will share the
                    // same IP and listen on port 3000.
                    SocketAddr::new(local_addr.ip(), 3000)
                };
                // Spawn a task to read and write to application process. The
                // POC is blocking (mostly), however, this is a good sanity
                // check to make sure we don't get in redirect loops where we
                // open a connection back to the proxy. Thanks @eliza.
                tokio::spawn(async move {
                    // Create connection to application process; read and write
                    // so we confirm traffic is flowing. We log out the peer and
                    // local addresses to confirm clientIP was spoofed.
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
                    }
                });
            }
            Err(e) => {
                info!(?e, "Error on conn accept");
                break; // just so the final statement is reachable.
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
    // Using a lib for iptables binding, the false there means we are not using
    // IPV6.
    let ipt = iptables::new(false)?;
    match mode {
        InterceptMode::Tproxy() => {
            // If we run in tproxy mode, then we work mostly with the mangle
            // table. We want to "divert" any packets that enter our netns.
            let chains = ipt.list_chains("mangle")?;
            info!(?chains, "Current state for mangle");
            if !ipt.chain_exists("mangle", "DIVERT_TEST")? {
                // Create a new DIVERT_TEST chain for our divert rules, if one
                // does not already exist.
                info!("Creating inexistent chain DIVERT_TEST");
                ipt.new_chain("mangle", "DIVERT_TEST")?;
            }

            // First, make sure we send packets to DIVERT_TEST as soon as they
            // hit PREROUTING. A packet will match and be sent to DIVERT_TEST
            // IFF it is a TCP socket and if there is an established (or
            // non-zero bound) listening socket (possibly with non-local address).
            // Basically matches any packet that is not SYN/ACK in the 3-way
            // handshake.
            ipt.append("mangle", "PREROUTING", "-p tcp -m socket -j DIVERT_TEST")?;
            // Once it's in DIVERT_TEST we mark the packet with '1', more on
            // this below in the fn.
            ipt.append("mangle", "DIVERT_TEST", "-j MARK --set-mark 1")?;
            // Finally, we accept the packet. This will send us back to
            // PREROUTING.
            ipt.append("mangle", "DIVERT_TEST", "-j ACCEPT")?;

            // Packet will go back to PREROUTING, where we add the TPROXY
            // target: if dst is not loopback, send the packet to our port. This
            // is the equivalent of nat in REDIRECT.
            // Note: bindings didn't play well with tproxy target so we exec
            // this cmd instead of relying on ipt bindings.
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

            // In tproxy mode we send to localhost; app process will _think_ it
            // talks to the client, when in reality it talks to the proxy.
            // Because the src IP will not match any local routes, reply packets
            // will be routed through eth0 (reply from app <> proxy).
            // The reply packets will never make it out on the network card;
            // there are 2 routing decisions: one after packet is generated, and
            // one after packet traverses firewall chains. Since UNIX kernel
            // does not allow martian packets (e.g local packet routed through
            // eth), it will be dropped before it reaches firewall. We set this
            // so that kernel routes packet even though it's "martian". We
            // should not have to do this in practice, since we will be sending
            // on the original dst.
            exec("sysctl", ["-w", "net/ipv4/conf/eth0/route_localnet=1"])?;
        }
        InterceptMode::Nat() => {
            // Same rules we have on inbound for Linkerd, without skip ports.
            // shameless self promotion:
            // https://linkerd.io/2.11/reference/iptables/#inbound
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
    // Whether we run NAT or TPROXY, we need to set up policy routing.
    // In TPROXY mode: this is necessary to intercept packets from client to
    // server, and to intercept packets from proxy to server.
    // In NAT mode: this is necessary only to make sure packets from proxy to
    // server stay local.
    // Since packets are marked, they will always stay local -- this is what we
    // want -- the server will want to send to a spoofed IP address so the
    // packets should not be routed through eth0.
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
    // These rules are needed to make sure proxy and server can talk to each
    // other when ip address is spoofed.
    // At first, when a packet hits PREROUTING, if it has a mark (i.e 1), that
    // mark will be turned into a connection mark. A connection mark is
    // associated _with the whole connection_ not just the packet, it makes sure
    // the connection always stays local. This means reply packets will be
    // considered too.
    // I am myself a bit unclear: normally, locally routed packets will NEVER
    // hit PREROUTING, except in this case...I think the first reply packet from
    // the server to the proxy (during 3wayshake) will be routed through here.
    // It's either that, or the first packet from proxy to server.
    // I tried to verify these things through ip route get: from proxy to server
    // we always have a local route, from server to proxy we have eth0 so I am
    // guessing the reply packet hits this. Either way, it's important we mark
    // the connection.
    // To solidfy: save packet mark into connection mark is what we're doing
    // here.
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

    // This reverts the previous decision, once a packet reaches OUTPUT, we
    // restore the packet mark from the connection mark. Again: routing
    // decisions are made before and after the OUTPUT chain. Past this point,
    // the connection is no longer marked, the packet is. When the kernel looks
    // up the route table, it will find the policy routing rules we put in place
    // earlier, since the packet will be marked as 1 => packet stays local.
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
    exec("iptables-legacy", ["-t", "nat", "-L"])?;
    // Route table 100 constructed for packets that are marked
    exec("ip", ["route", "show", "table", "100"])?;

    Ok(())
}

// Configure policy routing. Combined with marking, this allows us to treat any
// packet that is marked as a local packet, routing it over loopback interface.
// This is suggested to get tproxy running (assumption is that tproxy is on a
// box that routes traffic), but the necessity also extends to client spoofing,
// since we will want all packets to remain local instead of going to spoofed
// address. The idea is simple: marked packets will be consulted against the
// routing policy database and be acted on differently.
fn route_table() -> (
    std::result::Result<Output, io::Error>,
    std::result::Result<Output, io::Error>,
) {
    // fwmark = firewall mark, even older than iptables lol.
    // We first add a rule for policy routing that says any packet with mark 1
    // will be looked up in routing table '100' -- we can change the name here,
    // it can even be a String.
    let add_fwmark = Command::new("ip")
        .args(["rule", "add", "fwmark", "1", "lookup", "100"])
        .output();

    // In route table 100, we add a new route. The scope is 'local', it applies
    // to any IP address (0.0.0.0) and will be routed over loopback interface.
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

// Execute arbitrary commands.
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
