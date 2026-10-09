# Ztunnel

ztunnel is the Layer 4 traffic enforcement data plane for [Agentio](https://github.com/openkruise/agentio).

## How does it differ from Istio ztunnel?

- **Workload traffic policies** — enforces native TrafficPolicy references ordered by the control plane for every Workload. A bound Sandbox adds an inline policy stage before the shared Workload stage.
- **Non-TCP firewall enforcement** — translates traffic policies into inbound and outbound iptables or nftables rules for UDP, ICMP, and other supported non-TCP traffic, with automatic backend detection and live rule updates.
- **Per-workload sidecar deployment** — runs a dedicated ztunnel alongside each sandbox workload instead of as a node-level proxy, enforcing traffic policy at the workload boundary.
- **Workload certificates** — uses `spiffe://<trust-domain>/cluster/<cluster-id>/ns/<namespace>/workload/<pod-name>` for workload identities. Egress gateways retain service-account identities. Upgrade the Agentio control plane to support workload certificate requests before upgrading ztunnel.
