# Ztunnel

ztunnel is the Layer 4 traffic enforcement data plane for [Agentio](https://github.com/openkruise/agentio).

## How does it differ from Istio ztunnel?

- **Workload traffic policies** — enforces native TrafficPolicy references ordered by the control plane for every Workload. A bound Sandbox adds an inline policy stage before the shared Workload stage.
- **Non-TCP firewall enforcement** — translates traffic policies into inbound and outbound iptables or nftables rules for UDP, ICMP, and other supported non-TCP traffic, with automatic backend detection and live rule updates.
- **Per-workload sidecar deployment** — runs a dedicated ztunnel alongside each sandbox workload instead of as a node-level proxy, enforcing traffic policy at the workload boundary.

## Sandbox preparation

With `ENABLE_SANDBOX_MANAGER=true`, `PrepareSandbox` waits for the local Sandbox
configuration and Workload binding, then persists the registration before returning
gRPC `OK`. Success confirms local preparation, not EPE replica readiness or
completion of asynchronous firewall rule installation.

The file token module is optional and disabled by default. Agents deployments
using the file token protocol must explicitly set `SANDBOX_TOKEN_ENABLED=true`
alongside `ENABLE_SANDBOX_MANAGER=true`. When enabled, preparation additionally
requires a nonempty loaded token: a missing or empty token returns
`FAILED_PRECONDITION`; provision it and retry the same Sandbox ID. Token read or
JSON validation errors return `INTERNAL`, and token module initialization errors
fail proxy creation. Outbound requests carry identity fields in
`x-agentio-sandbox-metadata`. When disabled,
ztunnel does not create or watch the token directory, require a token for preparation,
or add the metadata header. Sandbox registration and the Sandbox ID header are unaffected.

In dedicated mode, tokens are read directly from `SANDBOX_TOKEN_PATH` (default:
`/var/opt/sandbox/agent-token/`), and registration is stored in `SANDBOX_STATE_DIR`.
The enabled token module creates the token directory when starting. The agents
producer writes `<md5(namespace-name)>.token` containing the token response JSON;
no Workload UID subdirectory or filename match with the xDS Sandbox ID is required.
The configured directory must expose the runtime's token files to ztunnel.
`SANDBOX_WATCHER_DEBOUNCE_MS` controls the enabled module's watcher debounce.
This preparation flow is validated for dedicated deployment; node-level token
delivery is outside this scope.

The manager owns the shared preparation operation used by RPC, including binding
checks and durable registration, and restores registered identities on startup.
Each outbound TCP connection or UDP session captures its ready Sandbox and cached
metadata before routing. Policy selection, pooling and HBONE headers use this
context; HBONE construction does not read token files. Unprepared connections
continue with Workload policies and carry no Sandbox identity or metadata.
Token readiness retries both missing files and cached empty files without waiting
for a watcher update. Token formats and explicit RPC preparation remain unchanged.

## Sandbox metadata header

Token files are JSON objects with nonempty string fields `accessToken` and
`sandboxClientId`. Other response fields are ignored. File loading parses these
fields and caches their metadata entries under the existing filename key;
multiple files remain separate Map entries. The token module contributes its
`agent-identity.*` entries to a shared `SandboxMetadata` collection. Other modules
can contribute their own namespaced entries to the same collection; outbound
connection setup serializes the combined collection as a Structured Fields
Dictionary with String values, defined by [RFC 9651](https://www.rfc-editor.org/rfc/rfc9651.html).
Replacing an existing key updates its value, so serialization emits each key only
once, in key order.
No JWT signature or expiry validation is performed by ztunnel.

```http
x-agentio-sandbox-metadata: agent-identity.access-token="eyJ...abc.def", agent-identity.sandbox-client-id="AbC+/xyz="
```

Consumers use a Structured Fields Dictionary parser, not comma splitting or a
JSON parser. Known entries must be String Items with nonempty values; Inner Lists
and other bare-item types are not accepted for those entries. Unknown keys and
parameters are ignored. Strings contain only printable ASCII (`0x20..=0x7e`);
quotes and backslashes are escaped by the standard serializer. Token loading
rejects controls and non-ASCII values without including credentials in errors.
Percent signs, commas, `+`, `/`, and `=` retain their literal meaning after SF
parsing; no percent-decoding or Base64 decoding is required.

The sender emits one header and omits it for empty metadata. Recipients combine
repeated field lines in order using the standard SF rules; duplicate Dictionary keys use the
last value, as specified by RFC 9651. A parse failure or an invalid known entry
invalidates the entire field. Missing or invalid metadata supplies no credentials
and must not bypass the gateway's authentication requirements.

The header is marked sensitive to avoid HTTP/2 dynamic-table indexing. It is an
internal credential header, separate from tracing `baggage`, and must not be
logged as ordinary metadata. The receiving gateway must support Structured Fields
before this change is deployed; neither the previous unquoted KV encoding nor
JSON is emitted.

The previous `x-agentio-sandbox-token` header containing Base64-encoded JSON is
no longer emitted. EPE must support the new header before deploying this change.
The token file format is unchanged. The Sandbox discovery ID is sent in
`x-agentio-sandbox-id`; the gateway captures it as `agentio.sandbox.id`.
The previous `x-agentio-sandbox-uid` header is no longer emitted.
Upgrade the sending ztunnel and receiving gateway together.

## DNS learning and destination FQDNs

DNS name tracking is opt-in: set `ENABLE_DNS_NAME_TRACKING=true` and restart
ztunnel to enable it. The default is `false`. It requires DNS proxying and supports
both dedicated and shared/inpod modes. Each workload proxy owns an independent
binding table; records are never shared across Pods. When disabled, no binding
table or periodic cleanup is created, local policy checks use IP addresses, and
the DNS candidates header is omitted. Normal DNS proxying and the resolver's DNS
response cache are unaffected.

Enabled instances learn the A/AAAA addresses returned to their local Workload.
Each `(query name, IP)` association is deduplicated
and retained until its remaining DNS TTL expires, including the shortest TTL in a
CNAME chain. Resolver cache hits do not reset TTLs. Older answers remain usable until
their own expiry, even if a later answer contains different addresses.

The learning table holds at most 16,384 associations per workload proxy. In inpod
mode, total node memory scales with the number of Pods. It removes expired
entries on subsequent DNS answers and every 60 seconds while idle, releasing the
HashMap capacity when empty. Matching checks expiry immediately, independently of
the cleanup interval. At capacity, existing live entries are retained and new
associations are omitted; `istio_dns_binding_overflow_total` counts these omissions.

`TrafficPolicy.Match.destination_fqdns` (protobuf field 4, local YAML
`destinationFqdns`) accepts exact DNS names in egress rules. Within each rule,
learned FQDNs and `destination_ips` are ORed; source and port conditions still apply.
Policy and rule order are unchanged. A FQDN-only rule without DNS evidence does not
match every destination. The control plane must retain such rules even when its own
DNS resolution has no addresses, and must only send them to compatible data planes.
DNS learning applies to outbound TCP authorization; firewall rules continue to use
the control-plane IP addresses.

Each outbound TCP connection or CONNECT-UDP session snapshots the valid names for
its original destination IP before gateway routing. HBONE CONNECT and CONNECT-UDP
requests carry this snapshot as one Structured Fields List of String Items,
omitted when empty:

```http
x-agentio-destination-dns-candidates: "api.example.com", "cdn.example.com"
```

Names are sorted, lowercase ASCII DNS presentation names without the trailing root
dot. Receivers use a Structured Fields List parser and then interpret the decoded
Strings as DNS presentation names, preserving DNS escapes. Inner Lists and other
bare-item types invalidate the entire field; unknown parameters are ignored.
Repeated field lines combine in order, and repeated names have the same meaning
as one occurrence. Invalid or missing fields supply no DNS evidence, so receivers
continue with their IP-based policy checks. The sender rejects a tunnel whose
header value would exceed 8,192 bytes;
it never silently truncates the candidate set. The header is marked sensitive to
avoid HTTP/2 dynamic-table indexing. It is generated from local DNS observations,
not forwarded from application headers, and is independent of the pooled HTTP/2
connection. Local TCP policy checks and the header use the same admission snapshot.
TTL expiry affects new connections; explicit policy updates still recheck existing
TCP connections using their captured names.

This header reports candidate names associated with the destination IP. It does
not establish the application's actual HTTP Host or TLS SNI. Gateways must accept
it only from authorized ztunnel peers over authenticated HBONE, bind it to the
CONNECT destination, and evaluate
their own policies. Shared IPs can have multiple candidate names; a missing header
means no DNS evidence, not permission to bypass policy. Gateway-side consumption
is a separate change in the gateway repository.

For a Linux/glibc learning-table resource probe, run
`cargo run --release --example dns_bindings -- 1000 8`. For a running-sidecar probe,
run `cargo test --test direct test_sidecar_dns_fqdn_resources -- --ignored --nocapture`
alone. These probes report incremental allocations rather than a total proxy memory
budget; the latter also includes the runtime and test DNS client.
