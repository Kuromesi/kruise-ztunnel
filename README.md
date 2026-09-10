# Ztunnel

ztunnel is the Layer 4 traffic enforcement data plane for [Agentio](https://github.com/openkruise/agentio).

## How does it differ from Istio ztunnel?

- **Outbound traffic authorization** — applies CLIENT-mode authorization policies to outbound connections, with namespace, global, and workload scope plus priority-ordered ALLOW/DENY decisions.
- **Non-TCP firewall enforcement** — translates priority authorization policies into inbound and outbound iptables or nftables rules for UDP, ICMP, and other supported non-TCP traffic, with automatic backend detection and live rule updates.
- **Per-workload sidecar deployment** — runs a dedicated ztunnel alongside each sandbox workload instead of as a node-level proxy, enforcing traffic policy at the workload boundary.

## Sidecar admin socket

By default, the admin API listens on localhost TCP port 15000. Containers in the
same Pod can access this listener. To use a filesystem Unix socket instead, set
these environment variables on the ztunnel container:

```yaml
env:
  - name: ENABLE_ADMIN_UNIX_SOCKET
    value: "true"
  - name: ADMIN_UNIX_SOCKET_PATH
    value: /var/run/ztunnel/admin.sock
```

`ENABLE_ADMIN_UNIX_SOCKET` defaults to `false`. `ADMIN_UNIX_SOCKET_PATH` defaults
to `/var/run/ztunnel/admin.sock` and must be an absolute file path when enabled.
In Unix socket mode, the TCP admin listener is disabled entirely; readiness and
metrics keep their existing listeners.

The parent directory must be writable by ztunnel and private to its container.
For a read-only root filesystem, mount a writable volume there **only in the
ztunnel container**, not in application containers. Newly created directories
use mode `0700`; the socket uses mode `0600`. Existing directory permissions are
not changed. Run admin clients as the ztunnel user (or an appropriately privileged
operator) inside the sidecar:

```shell
curl --unix-socket /var/run/ztunnel/admin.sock http://localhost/config_dump
curl --unix-socket /var/run/ztunnel/admin.sock -X POST http://localhost/quitquitquit
```

Update lifecycle hooks and diagnostic tools that call the TCP admin API to use
the socket; TCP port-forwarding cannot reach it. Normal shutdown removes the
socket, and startup reclaims stale socket files left by a crashed process.
An active socket, regular file, or symlink at the configured path causes startup
to fail instead of being replaced. Keep the parent directory under the sidecar's
control so other processes cannot replace files there.

## Building

Please use the same Rust version as the [`build-tools`](https://github.com/istio/tools/tree/master/docker/build-tools) image.
You can determine the version that the `build-tools` image uses by running the below command:

```shell
$ BUILD_WITH_CONTAINER=1 make rust-version
```

### TLS/Crypto provider

Ztunnel's TLS is built on [rustls](https://github.com/rustls/rustls).

Rustls has support for plugging in various crypto providers to meet various needs (compliance, performance, etc).

| Name                                               | How To Enable                                  |
|----------------------------------------------------|------------------------------------------------|
| [aws-lc](https://github.com/aws/aws-lc-rs)         | Default (or `--features tls-aws-lc`)           |
| [ring](https://github.com/briansmith/ring/)        | `--features tls-ring --no-default-features`    |
| [boring](https://github.com/cloudflare/boring)     | `--features tls-boring --no-default-features`  |
| [openssl](https://github.com/tofay/rustls-openssl) | `--features tls-openssl --no-default-features` |

In all options, only TLS 1.3 with cipher suites `TLS13_AES_256_GCM_SHA384` and `TLS13_AES_128_GCM_SHA256` is used.

#### `boring` FIPS

With the `boring` option, the FIPS version is used.
Please note this only implies the specific version of the library is used; FIPS compliance requires more than *just* using a specific library.

FIPS has
[strict requirements](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp4407.pdf)
to ensure that compliance is granted only to the exact binary tested.
FIPS compliance was [granted](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4407)
to an old version of BoringSSL that was tested with `Clang 12.0.0`.

Given that FIPS support will always have special environmental build requirements, we currently we work around this by vendoring OS/arch specific FIPS-compliant binary builds of `boringssl` in [](vendor/boringssl-fips/)

We vendor FIPS boringssl binaries for

- `linux/x86_64`
- `linux/arm64`

To use these vendored libraries and build ztunnel for either of these OS/arch combos, for the moment you must manually edit
[.cargo/config.toml](.cargo/config.toml) and change the values of BORING_BSSL_PATH and BORING_BSSL_INCLUDE_PATH under the `[env]` key to match the path to the vendored libraries for your platform, e.g:

##### For linux/x86_64

``` toml
BORING_BSSL_FIPS_PATH = { value = "vendor/boringssl-fips/linux_x86_64", force = true, relative = true }
BORING_BSSL_FIPS_INCLUDE_PATH = { value = "vendor/boringssl-fips/include/", force = true, relative = true }
```

##### For linux/arm64

``` toml
BORING_BSSL_FIPS_PATH = { value = "vendor/boringssl-fips/linux_arm64", force = true, relative = true }
BORING_BSSL_FIPS_INCLUDE_PATH = { value = "vendor/boringssl-fips/include/", force = true, relative = true }
```

Once that's done, you should be able to build:

``` shell
cargo build
```

This manual twiddling of environment vars is not ideal but given that the alternative is prefixing `cargo build` with these envs on every `cargo build/run`, for now we have chosen to hardcode these in `config.toml` - that may be revisited in the future depending on local pain and/or evolving `boring` upstream build flows.

Note that the Dockerfiles used to build these vendored `boringssl` builds may be found in the respective vendor directories, and can serve as a reference for the build environment needed to generate FIPS-compliant ztunnel builds.

A release build with this option can be built with `TLS_MODE=boring ./scripts/release.sh`.

## Development

Please refer to [this](./Development.md).

## Metrics

Ztunnel exposes a variety of metrics, at varying levels of stability.  They are
accessible by making an HTTP request to either "/stats/prometheus" or "/metrics" on port 15020.

**Core** metrics are considered stable APIs.

**Unstable** metrics may be changed. This includes removal, semantic changes, and label changes.

### Core metrics

#### Traffic metrics

- Tcp Bytes Sent (`istio_tcp_sent_bytes_total`): This is a `COUNTER` which measures the size of total bytes sent during response in case of a TCP connection.
- Tcp Bytes Received (`istio_tcp_received_bytes_total`): This is a `COUNTER` which measures the size of total bytes received during request in case of a TCP connection.
- Tcp Connections Opened (`istio_tcp_connections_opened_total`): This is a `COUNTER` incremented for every opened connection.
- Tcp Connections Closed (`istio_tcp_connections_closed_total`): This is a `COUNTER` incremented for every closed connection.

#### Meta metrics

- Istio build information (`istio_build`)

### Unstable metrics

#### DNS metrics

- DNS Requests (`istio_dns_requests_total`)
- DNS Upstream Requests (`istio_dns_upstream_requests_total`)
- DNS Upstream Failures (`istio_dns_upstream_failures_total`)
- DNS Upstream Request Duration (`istio_dns_upstream_request_duration_seconds`)
- On Demand DNS Requests (`istio_on_demand_dns_total`)

#### In-Pod metrics

- Active proxy count (`istio_active_proxy_count_total`)
- Pending proxy count (`istio_pending_proxy_count_total`)
- Proxies started (`istio_proxies_started_total`)
- Proxies stopped (`istio_proxies_stopped_total`)

#### XDS metrics

- XDS Connection terminations (`istio_xds_connection_terminations_total`)

## Logging

Ztunnel exposes a variety of logs, both operational and "access logs".

Logs are controlled by the `RUST_LOG` variable.
This can set all levels, or a specific target. For instance, `RUST_LOG=error,ztunnel::proxy=warn`.
Logs can be emitted in JSON format with `LOG_FORMAT=json`.
Access logs are under the `access` target.

An example access log looks like (with newlines for readability; the real logs are on one line):

```text
2024-04-11T15:38:42.182974Z  INFO access: connection complete
    src.addr=10.244.0.24:46238 src.workload="shell-6d8bcd654d-t88gp" src.namespace="default" src.identity="spiffe://cluster.local/ns/default/sa/default"
    dst.addr=10.244.0.42:15008 dst.hbone_addr=10.96.108.116:80 dst.service="echo.default.svc.cluster.local"
    direction="outbound" bytes_sent=67 bytes_recv=490 duration="13ms"
```

Access logs are emitted upon _completion_ of each connection.
Logs for connect _establishment_ are also logged (with less information) at `debug` level.

Currently, the access log format is considered unstable and subject to changes.

## License & Attribution

ztunnel is licensed under the [Apache License 2.0](LICENSE).

ztunnel is a modified derivative of [Istio ztunnel](https://github.com/istio/ztunnel) (Copyright Istio Authors, Apache License 2.0). The original Istio README is preserved at [README.istio](README.istio). Files derived from Istio that have been modified for this project carry a `Modifications Copyright 2026 The Kruise Authors` notice.

**Trademark notice:** "Istio" is a trademark of its respective owners. ztunnel is an independent project and is not affiliated with, sponsored by, or endorsed by the Istio project. References to Istio describe the origin of the code only.
