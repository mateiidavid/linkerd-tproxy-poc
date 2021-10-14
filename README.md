# TPROXY proof of concept for Linkerd

This proof of concept demonstrates how to use TPROXY target in iptables to
transparently redirect traffic, and spoof a client IP address. The main point
that it tries to illustrate is how to preserve the source IP of a client in
Kubernetes, when proxying traffic through a sidecar. For the full picture,
be sure to check out [linkerd/linkerd2#7089](https://github.com/linkerd/linkerd2/issues/7089)

At the moment, the poc can be run in two different modes: `nat` and `tproxy`:

- `nat` mode: will setup iptables rules at a nat level, as opposed to using the
  tproxy target. Traffic will be sent from proxy to server on the original
  address, hardcoded in (in a production proxy it would be through
  `SO_ORIGINAL_DST`).
- `tproxy` mode: will setup iptables rules at a mangle level, using the TPROXY
  target. Traffic will be sent from proxy to server over localhost; kernel eth0
  parameters are changed as a result to consider martian addresses.

Both modes will spoof client IP address and will set up policy routing and
make use of connection marking at the firewall level.

## Build & usage

```
tproxy-poc 0.1.0

USAGE:
    tproxy-poc [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --addr <addr>    Address to listen on for inbound packets defaults to port 5000 [default: 0.0.0.0:5000]
        --mode <mode>    Intercept mode for tproxy poc. It can either be 'nat' or 'tproxy'; different modes will set up
                         iptables differently, client IP will still be spoofed

```

(**Note**: I cut some corners, I _do not_ recommend setting the address to anything else)

The poc contains two separate images: the actual tproxy poc that will setup
iptables and proxy traffic, and an echo-server, that doesn't even echo
anything, it reads off the stream and sends some random bytes back. The point
of these two is to test that connections can be established and addresses
spoofed.

To make it easier to build, there is a makefile present, it will build and load
the images in a k3d cluster.

**Example**
```bash
# 'make all' will build 'tproxy-poc', 'echo-server' and load the images in a k3d cluster.
# the name of the cluster can be overwritten through CLUSTER_NAME, the default is 'dev'.
# Both images will be tagged as 'latest', the provided manifests pull in the latest image.
#
$ CLUSTER_NAME="dev" make all

# If there is an existing deployment, 'tproxy' can be built separately, if you want
# to see any new changes in action. This will build and load.
#
$ make tproxy

# If you are using kind, you can build the images separately and then load them in.
# image tags can also be overridden, just make sure to update the manifests.
#
$ TPROXY_IMAGE=v0.2 make tproxy-poc
$ make server
$ CLUSTER_NAME=foo make kind-load

# Finally, to see it in action, you can apply either manifest from k8s/deploy
#
# will deploy tproxy-poc in tproxy mode
$ kubectl apply -f k8s/deploy-tproxy.yaml

# will deploy tproxy-poc in nat mode
$ kubectl apply -f k8s/deploy-nat.yaml

# Quickest way to get started
# 
$ k3d cluster create dev
$ make all
$ kubectl apply -f k8s/deploy-tproxy.yaml
```

## Testing

To help with testing, there's a curl pod included in the `k8s` directory.
Simply apply the curl pod, exec onto it and send requests to a pod containing
`tproxy-poc`. I suggest bypassing any virtual IPs and sending directly to the
pod IP. You may also use `nc` instead of curl, it shouldn't matter much.

Look out for log messages that record what the local and peer addresses of a
connection are.
