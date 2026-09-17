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

use std::fmt::{self, Display, Formatter};
use std::net::SocketAddr;

use crate::identity::Identity;
use crate::strng::Strng;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, Hash, Ord, PartialOrd)]
pub enum Direction {
    Inbound,
    Outbound,
}

impl Default for Direction {
    fn default() -> Self {
        // Inbound is the original (pre-direction) behavior path; defaulting
        // here keeps `Connection::default()` matching the legacy semantics.
        Direction::Inbound
    }
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize)]
pub struct Connection {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub src_identity: Option<Identity>,
    pub dst_network: Strng,
    pub direction: Direction,
}

struct OptionDisplay<'a, T>(&'a Option<T>);

impl<T: Display> Display for OptionDisplay<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.0 {
            None => write!(f, "None"),
            Some(i) => write!(f, "{i}"),
        }
    }
}

impl Display for Connection {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}({})->{}",
            self.src,
            OptionDisplay(&self.src_identity),
            self.dst
        )
    }
}
