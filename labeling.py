# Copyright 2023 Two Six Technologies

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pandas import DataFrame
from scapy.layers.inet import UDP

from mice_base.fe_types import Pkt, FlowID, Flows

from typing import List, Set

SIP = 0
DIP = 1
SPORT = 2
DPORT = 3
LENGTH = 4


def match_forward(flow, clients, proxies) -> bool:
    return flow[SIP] in clients and flow[DIP] in proxies


def match_backward(flow, clients, proxies) -> bool:
    return flow[DIP] in clients and flow[SIP] in proxies


def is_fwd(fid: FlowID) -> bool:
    return fid[2] > fid[3]


def is_bwd(fid: FlowID) -> bool:
    return fid[3] > fid[2]


def label_forward(
    fids: List[FlowID], fwd_idxs: Set[int], clients: List[str], proxies: List[str]
) -> DataFrame:
    fwd_labels = [idx in fwd_idxs for idx in range(len(fids))]
    flow_labels = [match_forward(fid, clients, proxies) for fid in fids]
    return DataFrame(
        zip(fwd_labels, flow_labels, fids),
        columns=["right_direction", "label", "flowid"],
    )


def label_backward(
    fids: List[FlowID], bwd_idxs: Set[int], clients: List[str], proxies: List[str]
) -> DataFrame:
    bwd_labels = [idx in bwd_idxs for idx in range(len(fids))]
    flow_labels = [match_backward(fid, clients, proxies) for fid in fids]

    return DataFrame(
        zip(bwd_labels, flow_labels, fids),
        columns=["right_direction", "label", "flowid"],
    )


def label_both(flows: Flows, clients: List[str], proxies: List[str]) -> DataFrame:
    fids = [fid for fid, _ in flows]
    direction_labels = [True for fid in fids]
    flow_labels = [
        match_backward(fid, clients, proxies) or match_forward(fid, clients, proxies)
        for fid in fids
    ]

    return DataFrame(
        zip(direction_labels, flow_labels, fids),
        columns=["right_direction", "label", "flowid"],
    )


def label_snowflake(flows: Flows, clients: List[str], background: List[str]):
    fids = [fid for fid, _ in flows]
    direction_labels = [True] * len(flows)
    flow_labels = [
        bool(
            flow[0].haslayer(UDP)
            and (fid.sip in clients or fid.dip in clients)
            and (fid.sip not in background and fid.dip not in background)
        )
        for fid, flow in flows
    ]

    return DataFrame(
        zip(direction_labels, flow_labels, fids),
        columns=["right_direction", "label", "flowid"],
    )
