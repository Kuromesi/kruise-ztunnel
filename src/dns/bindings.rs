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

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::Duration;

use hickory_proto::rr::{Name, RData};
use tokio::time::Instant;

use crate::dns::resolver::Answer;
use crate::strng::Strng;

/// Per-sidecar DNS observations, independent of the resolver's response cache.
#[derive(Debug, Default)]
pub struct DnsBindings(RwLock<Bindings>);

#[derive(Debug, Default)]
struct Bindings {
    by_ip: HashMap<IpAddr, Vec<(Strng, Instant)>>,
    len: usize,
    next_expiry: Option<Instant>,
}

pub const MAX_BINDINGS: usize = 16_384;
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

impl Bindings {
    fn remove_expired(&mut self, now: Instant) {
        if self.next_expiry.is_none_or(|expiry| expiry > now) {
            return;
        }
        self.by_ip.retain(|_, names| {
            names.retain(|(_, expires)| *expires > now);
            !names.is_empty()
        });
        self.len = self.by_ip.values().map(Vec::len).sum();
        self.next_expiry = self
            .by_ip
            .values()
            .flatten()
            .map(|(_, expiry)| *expiry)
            .min();
        if self.len == 0 {
            self.by_ip = HashMap::new();
        }
    }
}

pub(crate) fn canonical_name(name: &Name) -> Strng {
    let mut name = name.to_lowercase();
    name.set_fqdn(false);
    name.to_ascii().into()
}

impl DnsBindings {
    /// Learn only addresses reachable from the query through its CNAME chain.
    /// Returns the number of new associations omitted because capacity was exhausted.
    pub fn observe(&self, query: &Name, answer: &Answer, now: Instant) -> usize {
        let records: Vec<_> = answer.record_iter().collect();
        let mut target = query.clone();
        let mut chain_ttl = u32::MAX;
        for _ in 0..records.len() {
            let Some(record) = records
                .iter()
                .find(|r| r.name == target && matches!(r.data, RData::CNAME(_)))
            else {
                break;
            };
            let RData::CNAME(cname) = &record.data else {
                unreachable!()
            };
            target = cname.0.clone();
            chain_ttl = chain_ttl.min(record.ttl);
        }
        let name = canonical_name(query);
        let mut bindings = self.0.write().unwrap();
        bindings.remove_expired(now);
        let mut omitted = 0;
        for record in records {
            if record.name != target {
                continue;
            }
            let ip = match &record.data {
                RData::A(a) => IpAddr::V4(a.0),
                RData::AAAA(a) => IpAddr::V6(a.0),
                _ => continue,
            };
            let ttl = chain_ttl.min(record.ttl);
            if ttl == 0 {
                continue;
            }
            let expires = now + Duration::from_secs(ttl.into());
            if let Some((_, previous)) = bindings
                .by_ip
                .get_mut(&ip)
                .and_then(|names| names.iter_mut().find(|(n, _)| *n == name))
            {
                // Another client in this Pod may still hold the earlier answer.
                *previous = (*previous).max(expires);
            } else if bindings.len < MAX_BINDINGS {
                bindings
                    .by_ip
                    .entry(ip)
                    .or_insert_with(|| Vec::with_capacity(1))
                    .push((name.clone(), expires));
                bindings.len += 1;
            } else {
                omitted += 1;
                continue;
            }
            bindings.next_expiry = Some(
                bindings
                    .next_expiry
                    .map_or(expires, |previous| previous.min(expires)),
            );
        }
        omitted
    }

    /// Snapshot at connection admission; reads never extend DNS lifetimes.
    pub fn lookup(&self, ip: IpAddr, now: Instant) -> Vec<Strng> {
        let bindings = self.0.read().unwrap();
        let mut names: Vec<_> = bindings
            .by_ip
            .get(&ip)
            .into_iter()
            .flatten()
            .filter(|(_, expires)| *expires > now)
            .map(|(name, _)| name.clone())
            .collect();
        names.sort_unstable();
        names
    }

    /// Polled by the DNS server, so maintenance stops when its listener drains.
    pub(crate) async fn run_cleanup(&self) {
        let mut interval =
            tokio::time::interval_at(Instant::now() + CLEANUP_INTERVAL, CLEANUP_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            self.0.write().unwrap().remove_expired(Instant::now());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::Record;
    use hickory_proto::rr::rdata::{A, AAAA, CNAME};

    fn name(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    fn answer(host: &str, ttl: u32, ips: &[&str]) -> Answer {
        Answer::new(
            ips.iter()
                .map(|ip| {
                    let data = match ip.parse().unwrap() {
                        IpAddr::V4(ip) => RData::A(A(ip)),
                        IpAddr::V6(ip) => RData::AAAA(AAAA(ip)),
                    };
                    Record::from_rdata(name(host), ttl, data)
                })
                .collect(),
            false,
        )
    }

    #[test]
    fn learns_all_addresses_and_preserves_unexpired_answers() {
        let cache = DnsBindings::default();
        let now = Instant::now();
        cache.observe(
            &name("API.Example.COM."),
            &answer(
                "api.example.com.",
                60,
                &["192.0.2.1", "192.0.2.2", "2001:db8::1"],
            ),
            now,
        );
        for ip in ["192.0.2.1", "192.0.2.2", "2001:db8::1"] {
            assert_eq!(cache.lookup(ip.parse().unwrap(), now), ["api.example.com"]);
        }
        cache.observe(
            &name("api.example.com"),
            &answer("api.example.com", 60, &["192.0.2.3"]),
            now + Duration::from_secs(20),
        );
        assert!(
            !cache
                .lookup("192.0.2.1".parse().unwrap(), now + Duration::from_secs(59))
                .is_empty()
        );
        assert!(
            cache
                .lookup("192.0.2.1".parse().unwrap(), now + Duration::from_secs(60))
                .is_empty()
        );
        assert!(
            !cache
                .lookup("192.0.2.3".parse().unwrap(), now + Duration::from_secs(79))
                .is_empty()
        );
        assert!(
            DnsBindings::default()
                .lookup("192.0.2.1".parse().unwrap(), now)
                .is_empty()
        );
    }

    #[test]
    fn follows_cname_chain_and_ignores_unrelated_addresses() {
        let cache = DnsBindings::default();
        let now = Instant::now();
        let mut records = vec![
            Record::from_rdata(
                name("api.example.com"),
                10,
                RData::CNAME(CNAME(name("edge.example.com"))),
            ),
            Record::from_rdata(
                name("edge.example.com"),
                20,
                RData::CNAME(CNAME(name("cdn.example.com"))),
            ),
        ];
        records.extend(
            answer("cdn.example.com", 60, &["192.0.2.1", "2001:db8::1"])
                .record_iter()
                .cloned(),
        );
        records.extend(
            answer("unrelated.example.com", 60, &["192.0.2.99"])
                .record_iter()
                .cloned(),
        );
        cache.observe(&name("api.example.com"), &Answer::new(records, false), now);
        assert_eq!(
            cache.lookup("192.0.2.1".parse().unwrap(), now),
            ["api.example.com"]
        );
        assert!(cache.lookup("192.0.2.99".parse().unwrap(), now).is_empty());
        assert!(
            cache
                .lookup("192.0.2.1".parse().unwrap(), now + Duration::from_secs(10))
                .is_empty()
        );
    }

    #[test]
    fn cache_hits_do_not_reset_ttl_and_shared_ips_keep_all_names() {
        let cache = DnsBindings::default();
        let now = Instant::now();
        cache.observe(
            &name("a.example.com"),
            &answer("a.example.com", 60, &["192.0.2.1"]),
            now,
        );
        cache.observe(
            &name("a.example.com"),
            &answer("a.example.com", 40, &["192.0.2.1"]),
            now + Duration::from_secs(20),
        );
        cache.observe(
            &name("b.example.com"),
            &answer("b.example.com", 60, &["192.0.2.1"]),
            now,
        );
        cache.observe(
            &name("zero.example.com"),
            &answer("zero.example.com", 0, &["192.0.2.1"]),
            now,
        );
        assert_eq!(
            cache.lookup("192.0.2.1".parse().unwrap(), now),
            ["a.example.com", "b.example.com"]
        );
        assert_eq!(cache.0.read().unwrap().len, 2);
        assert!(
            cache
                .lookup("192.0.2.1".parse().unwrap(), now + Duration::from_secs(60))
                .is_empty()
        );
    }

    #[test]
    fn capacity_preserves_live_bindings_and_reclaims_expired_ones() {
        let cache = DnsBindings::default();
        let now = Instant::now();
        for i in 0..MAX_BINDINGS {
            let host = format!("{i}.example.com");
            assert_eq!(
                cache.observe(&name(&host), &answer(&host, 10, &["192.0.2.1"]), now),
                0
            );
        }
        let extra = answer("extra.example.com", 10, &["192.0.2.2"]);
        assert_eq!(cache.observe(&name("extra.example.com"), &extra, now), 1);
        assert_eq!(cache.0.read().unwrap().len, MAX_BINDINGS);
        assert_eq!(
            cache.observe(
                &name("extra.example.com"),
                &extra,
                now + Duration::from_secs(10)
            ),
            0
        );
        assert_eq!(cache.0.read().unwrap().len, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_cleanup_reclaims_expired_records_and_empty_table_capacity() {
        let cache = std::sync::Arc::new(DnsBindings::default());
        let now = Instant::now();
        cache.observe(
            &name("short.example.com"),
            &answer("short.example.com", 10, &["192.0.2.1"]),
            now,
        );
        cache.observe(
            &name("long.example.com"),
            &answer("long.example.com", 120, &["192.0.2.1"]),
            now,
        );
        let task = tokio::spawn({
            let cache = cache.clone();
            async move { cache.run_cleanup().await }
        });
        tokio::task::yield_now().await;
        tokio::time::advance(CLEANUP_INTERVAL).await;
        tokio::task::yield_now().await;
        assert_eq!(cache.0.read().unwrap().len, 1);
        assert_eq!(
            cache.lookup("192.0.2.1".parse().unwrap(), Instant::now()),
            ["long.example.com"]
        );
        tokio::time::advance(CLEANUP_INTERVAL).await;
        tokio::task::yield_now().await;
        assert_eq!(cache.0.read().unwrap().len, 0);
        assert_eq!(cache.0.read().unwrap().by_ip.capacity(), 0);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
}
