# Ztunnel

ztunnel is the Layer 4 traffic enforcement data plane for [Agentio](https://github.com/openkruise/agentio).

## How does it differ from Istio ztunnel?

- **Workload traffic policies** — enforces native TrafficPolicy references ordered by the control plane for every Workload. A bound Sandbox adds an inline policy stage before the shared Workload stage.
- **Non-TCP firewall enforcement** — translates traffic policies into inbound and outbound iptables or nftables rules for UDP, ICMP, and other supported non-TCP traffic, with automatic backend detection and live rule updates.
- **Per-workload sidecar deployment** — runs a dedicated ztunnel alongside each sandbox workload instead of as a node-level proxy, enforcing traffic policy at the workload boundary.

## TrafficPolicy enforcement during gateway migration

`ENABLE_EGRESS_TRAFFIC_POLICY` defaults to `true`, preserving existing enforcement after an upgrade. Set it to `false` and restart ztunnel to disable outbound Workload and Sandbox TrafficPolicy checks in the proxy (including existing-connection policy rechecks) and outbound native firewall policy rules. Inbound policy enforcement and xDS subscriptions remain enabled. The variable accepts `true` or `false`; invalid values fail startup.

When moving outbound enforcement to Porter, first enable `ENABLE_TRAFFIC_POLICY=true` on all Porter instances and verify gateway enforcement, then disable ztunnel egress enforcement. Reverse that order when rolling back. Only disable local enforcement when the relevant outbound traffic is forced through the gateway; direct traffic and protocols the gateway does not enforce otherwise lose outbound TrafficPolicy protection. Porter currently authorizes new CONNECT requests and does not revoke existing connections on policy updates.
