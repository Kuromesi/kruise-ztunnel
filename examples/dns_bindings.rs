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

//! Linux/glibc resource probe: cargo run --profile quick-release --example dns_bindings -- 1000 8
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use {
    hickory_proto::rr::{Name, RData, Record, rdata::A},
    std::hint::black_box,
    std::net::{IpAddr, Ipv4Addr},
    std::time::Instant,
    ztunnel::dns::bindings::{DnsBindings, MAX_BINDINGS},
    ztunnel::dns::resolver::Answer,
};

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn allocated_bytes() -> usize {
    // mallinfo2 reports live glibc allocations, excluding the probe's freed DNS answers.
    let info = unsafe { libc::mallinfo2() };
    info.uordblks + info.hblkhd
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn rss_kib() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")
                .map(|v| v.split_whitespace().next().unwrap().parse().unwrap())
        })
        .unwrap()
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let domains: usize = args.get(1).map(|s| s.parse().unwrap()).unwrap_or(1000);
    let ips_per_domain: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(8);
    assert!(domains > 0 && ips_per_domain > 0 && domains * ips_per_domain < u32::MAX as usize);
    let cache = DnsBindings::default();
    let now = tokio::time::Instant::now();
    let address = |i: usize| IpAddr::V4(Ipv4Addr::from(i as u32 + 1));
    let baseline_rss = rss_kib();
    let baseline_heap = allocated_bytes();
    let start = Instant::now();
    let mut omitted = 0;
    for d in 0..domains {
        let name = Name::from_ascii(format!("api-{d}.example.com.")).unwrap();
        let records = (0..ips_per_domain)
            .map(|i| {
                let IpAddr::V4(ip) = address(d * ips_per_domain + i) else {
                    unreachable!()
                };
                Record::from_rdata(name.clone(), 60, RData::A(A(ip)))
            })
            .collect();
        omitted += cache.observe(&name, &Answer::new(records, false), now);
    }
    let observe_ns = start.elapsed().as_nanos() / domains as u128;
    let heap_delta = allocated_bytes().saturating_sub(baseline_heap);
    let rss_delta = rss_kib().saturating_sub(baseline_rss);
    let retained = (domains * ips_per_domain).min(MAX_BINDINGS);
    assert_eq!(omitted, domains * ips_per_domain - retained);
    assert_eq!(cache.lookup(address(0), now).len(), 1);
    let iterations = 200_000;
    let start = Instant::now();
    for i in 0..iterations {
        black_box(cache.lookup(black_box(address(i % retained)), now));
    }
    let lookup_ns = start.elapsed().as_nanos() / iterations as u128;
    assert!(
        cache
            .lookup(address(0), now + std::time::Duration::from_secs(60))
            .is_empty()
    );
    println!(
        "{}",
        serde_json::json!({
            "domains": domains, "ips_per_domain": ips_per_domain, "retained": retained,
            "omitted": omitted, "live_heap_delta_bytes": heap_delta,
            "rss_delta_kib": rss_delta, "observe_ns_per_answer": observe_ns,
            "lookup_ns_per_connection": lookup_ns, "capacity": MAX_BINDINGS,
        })
    );
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn main() {
    panic!("this resource probe requires Linux/glibc");
}
