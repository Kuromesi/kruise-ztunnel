// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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

#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message;
use ztunnel::rbac::TrafficPolicy;
use ztunnel::sandbox::discovery::Sandbox;
use ztunnel::state::workload::Workload;
use ztunnel::xds::agentio::sandbox::Sandbox as XdsSandbox;
use ztunnel::xds::agentio::security::TrafficPolicy as XdsTrafficPolicy;
use ztunnel::xds::istio::workload::Workload as XdsWorkload;

fuzz_target!(|data: &[u8]| {
    let _ = run_workload(data);
    let _ = run_sandbox(data);
    let _ = run_traffic_policy(data);
});

fn run_workload(data: &[u8]) -> anyhow::Result<()> {
    Workload::try_from(XdsWorkload::decode(data)?)?;
    Ok(())
}

fn run_sandbox(data: &[u8]) -> anyhow::Result<()> {
    Sandbox::try_from(XdsSandbox::decode(data)?)?;
    Ok(())
}

fn run_traffic_policy(data: &[u8]) -> anyhow::Result<()> {
    TrafficPolicy::try_from(XdsTrafficPolicy::decode(data)?)?;
    Ok(())
}
