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
fields and caches their encoded metadata entries under the existing filename key;
multiple files remain separate Map entries. The token module contributes its
`agent-identity.*` entries to a shared `SandboxMetadata` collection. Other modules
can contribute their own namespaced entries to the same collection; outbound
connection setup serializes the combined collection into one header. Values
are encoded at insertion and are not encoded again during merging. Replacing an
existing key updates its value, so serialization emits each key only once.
No JWT signature or expiry validation is performed by ztunnel.

```http
x-agentio-sandbox-metadata: agent-identity.access-token=eyJ...abc.def,agent-identity.sandbox-client-id=AbC+/xyz=
```

Values follow [W3C baggage value encoding](https://www.w3.org/TR/baggage/#value):
percent-encode `%`, whitespace, comma, semicolon, double quote, backslash, control
bytes, and UTF-8 bytes outside ASCII. Literal `+`, `/`, and `=` are preserved.
Consumers split entries at commas, split each entry at the first `=`, then
percent-decode values once; `+` must not be decoded as a space. Keys are unique;
consumers should reject duplicate keys and may ignore unknown keys. The header is
an internal credential header, separate from tracing `baggage`, and must not be
logged as ordinary metadata.

The previous `x-agentio-sandbox-token` header containing Base64-encoded JSON is
no longer emitted. EPE must support the new header before deploying this change.
The token file format is unchanged. The Sandbox discovery ID is sent in
`x-agentio-sandbox-id`; the gateway captures it as `agentio.sandbox.id`.
The previous `x-agentio-sandbox-uid` header is no longer emitted.
Upgrade the sending ztunnel and receiving gateway together.
