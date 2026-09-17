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

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PodStateLabels {
    pub state: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ApplyResultLabels {
    pub result: &'static str,
}

#[derive(Clone)]
pub struct Metrics {
    pub pods: Family<PodStateLabels, Gauge>,
    pub apply_total: Family<ApplyResultLabels, Counter>,
    pub apply_duration: Family<ApplyResultLabels, Histogram>,
    pub rebuild_duration: Histogram,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let pods = Family::default();
        registry.register(
            "firewall_pods",
            "Number of pods by firewall state",
            pods.clone(),
        );

        let apply_total = Family::default();
        registry.register(
            "firewall_apply_total",
            "Total number of firewall rule apply operations",
            apply_total.clone(),
        );

        let apply_duration = Family::<ApplyResultLabels, Histogram>::new_with_constructor(|| {
            Histogram::new(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0])
        });
        registry.register(
            "firewall_apply_duration_seconds",
            "Duration of a single firewall rule apply operation",
            apply_duration.clone(),
        );

        let rebuild_duration = Histogram::new(vec![0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0]);
        registry.register(
            "firewall_rebuild_duration_seconds",
            "Duration of a full firewall rebuild cycle",
            rebuild_duration.clone(),
        );

        Self {
            pods,
            apply_total,
            apply_duration,
            rebuild_duration,
        }
    }

    pub fn record_apply(&self, success: bool, duration_secs: f64) {
        let result = if success { "success" } else { "error" };
        let labels = ApplyResultLabels { result };
        self.apply_total.get_or_create(&labels).inc();
        self.apply_duration
            .get_or_create(&labels)
            .observe(duration_secs);
    }

    pub fn update_pod_counts(&self, enrolled: usize, pending: usize, init_failed: usize) {
        self.pods
            .get_or_create(&PodStateLabels { state: "enrolled" })
            .set(enrolled as i64);
        self.pods
            .get_or_create(&PodStateLabels { state: "pending" })
            .set(pending as i64);
        self.pods
            .get_or_create(&PodStateLabels {
                state: "init_failed",
            })
            .set(init_failed as i64);
    }
}
