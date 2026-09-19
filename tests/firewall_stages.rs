// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Real packet checks for the Sandbox gate and ordered Workload stage.
//! Run as root on Linux; each test owns and removes its network namespaces.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use ztunnel::firewall::{Backend, IptBackend, NftBackend, RuleSet};
use ztunnel::rbac::{TrafficPolicy, firewall_rulesets};
use ztunnel::xds::agentio::security::{TrafficPolicy as WirePolicy, traffic_policy as proto};

fn command(args: &[&str]) {
    let output = Command::new(args[0]).args(&args[1..]).output().unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct Network {
    client: String,
    server: String,
    echo: Option<Child>,
}

impl Drop for Network {
    fn drop(&mut self) {
        if let Some(child) = self.echo.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        for name in [&self.client, &self.server] {
            let _ = Command::new("ip").args(["netns", "del", name]).output();
        }
    }
}

impl Network {
    fn new(backend: &str) -> Self {
        let mut network = Self {
            client: format!("zt-stage-{}-{backend}-c", std::process::id()),
            server: format!("zt-stage-{}-{backend}-s", std::process::id()),
            echo: None,
        };
        command(&["ip", "netns", "add", &network.client]);
        command(&["ip", "netns", "add", &network.server]);
        command(&[
            "ip",
            "-n",
            &network.client,
            "link",
            "add",
            "client",
            "type",
            "veth",
            "peer",
            "name",
            "server",
        ]);
        command(&[
            "ip",
            "-n",
            &network.client,
            "link",
            "set",
            "server",
            "netns",
            &network.server,
        ]);
        for (ns, link, addr) in [
            (&network.client, "client", "10.254.0.1/24"),
            (&network.server, "server", "10.254.0.2/24"),
        ] {
            command(&["ip", "-n", ns, "addr", "add", addr, "dev", link]);
            command(&["ip", "-n", ns, "link", "set", link, "up"]);
            command(&["ip", "-n", ns, "link", "set", "lo", "up"]);
        }
        let mut echo = Command::new("ip").args(["netns", "exec", &network.server, "python3", "-u", "-c",
            "import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ns.bind(('10.254.0.2',12345))\nprint('ready',flush=True)\nwhile True:\n data,peer=s.recvfrom(1024)\n s.sendto(data,peer)"])
            .stdout(Stdio::piped()).spawn().unwrap();
        let mut ready = String::new();
        BufReader::new(echo.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        network.echo = Some(echo);
        assert_eq!(ready.trim(), "ready");
        network
    }

    fn assert_traffic(&self, allowed: bool, case: &str) {
        // Every probe opens a fresh flow so conntrack's established bypass cannot
        // make a previous ALLOW hide a newly applied DENY.
        for args in [
            vec![
                "python3",
                "-c",
                "import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ns.settimeout(1)\ns.sendto(b'policy',('10.254.0.2',12345))\nassert s.recv(1024)==b'policy'",
            ],
            vec!["ping", "-n", "-c", "1", "-W", "1", "10.254.0.2"],
        ] {
            let output = Command::new("ip")
                .args(["netns", "exec", &self.client])
                .args(&args)
                .output()
                .unwrap();
            assert_eq!(
                output.status.success(),
                allowed,
                "{case} {args:?}: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

fn policy(ingress: bool, action: Option<proto::Action>) -> TrafficPolicy {
    let rules = proto::RuleSet {
        rules: action
            .into_iter()
            .map(|action| proto::Rule {
                action: action.into(),
                r#match: Some(proto::Match::default()),
            })
            .collect(),
    };
    TrafficPolicy::try_from(if ingress {
        WirePolicy {
            ingress: Some(rules),
            ..Default::default()
        }
    } else {
        WirePolicy {
            egress: Some(rules),
            ..Default::default()
        }
    })
    .unwrap()
}

#[test_case::test_case("iptables")]
#[test_case::test_case("nftables")]
#[tokio::test]
#[ignore = "requires root, iproute2, iptables, nftables, python3 and ping"]
async fn sandbox_allow_requires_workload_allow(kind: &str) {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "run this integration test as root"
    );
    let network = Network::new(kind);
    for ingress in [false, true] {
        let path = format!(
            "/var/run/netns/{}",
            if ingress {
                &network.server
            } else {
                &network.client
            }
        );
        let backend: Box<dyn Backend> = match kind {
            "iptables" => Box::new(IptBackend::new().in_netns(path)),
            "nftables" => Box::new(NftBackend::new().in_netns(path)),
            _ => unreachable!(),
        };
        backend.init().await.unwrap();
        let allow = policy(ingress, Some(proto::Action::Allow));
        let deny = policy(ingress, Some(proto::Action::Deny));
        let empty = policy(ingress, None);
        for (case, inline, system, allowed) in [
            ("both allow", Some(&allow), Some(&allow), true),
            ("inline allow/system deny", Some(&allow), Some(&deny), false),
            ("inline deny/system allow", Some(&deny), Some(&allow), false),
            ("empty inline direction", Some(&empty), Some(&allow), false),
            ("missing referenced body", Some(&allow), None, false),
            ("ordinary workload allow", None, Some(&allow), true),
            ("ordinary workload deny", None, Some(&deny), false),
        ] {
            let mut rules = firewall_rulesets(std::iter::once(("system", system)));
            rules.inline_rules = inline
                .map(|policy| firewall_rulesets(std::iter::once(("inline", Some(policy)))).rules)
                .unwrap_or_default();
            backend.apply(&rules).await.unwrap();
            backend.apply(&rules).await.unwrap(); // Reconciliation must remain idempotent.
            network.assert_traffic(allowed, &format!("{kind} ingress={ingress} {case}"));
        }
        backend.apply(&RuleSet::default()).await.unwrap();
        network.assert_traffic(true, "policy removal");
        backend.cleanup().await.unwrap();
    }
}
