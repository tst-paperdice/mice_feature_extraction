#!/usr/bin/env python

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

import argparse
import inspect
import os
import traceback
from collections import Counter
from abc import ABC

import numpy as np
import pandas as pd
from scapy.all import *
from scapy.layers.inet import TCP, UDP
from scipy.stats import entropy


# TODO: DEBUG remove this code. install package instead
# append the path of the parent directory
# sys.path.append("..")

# MICE imports
import mice_base
from mice_base.features.fe_types import Pkt, Values, FlowID, Flows
import labeling
from mice_base.features.BaseFeatures.PerPacketFeature import PerPacketFeature
import netml_parser as nmlp
import windowed as win

from typing import Tuple, List, Iterable

SIP = 0
DIP = 1
SPORT = 2
DPORT = 3
PROTO = 4
SS_PORT = 48388


def _entropy_helper(pkt: Pkt, end=-1, begin=0, layer=scapy.all.Raw) -> float:
    if not pkt.haslayer(layer):
        return 0.0

    pk = list(Counter(pkt.payload[layer].original[begin:end]).values())
    return entropy(pk, base=2)


def _flag_helper(pkt: Pkt, flag: str, layer) -> int:
    if not pkt.haslayer(layer):
        return False

    return flag in pkt.payload[layer].flags


def get_syn(pkts: List[Pkt]) -> Values:
    return [_flag_helper(pkt, "S", TCP) for pkt in pkts]


def get_ack(pkts: List[Pkt]) -> Values:
    return [_flag_helper(pkt, "A", TCP) for pkt in pkts]


def get_synack(pkts: List[Pkt]) -> Values:
    return [
        (_flag_helper(pkt, "S", TCP) and _flag_helper(pkt, "A", TCP)) for pkt in pkts
    ]


def get_psh(pkts: List[Pkt]) -> Values:
    return [_flag_helper(pkt, "P", TCP) for pkt in pkts]


def get_urg(pkts: List[Pkt]) -> Values:
    return [_flag_helper(pkt, "U", TCP) for pkt in pkts]


def get_entropy(pkts: List[Pkt]) -> Values:
    return [_entropy_helper(pkt) for pkt in pkts]


def get_iat(pkts: List[Pkt]) -> Values:
    return list(np.diff([float(pkt.time) for pkt in pkts])) + [0.0]


def get_size(pkts: List[Pkt]) -> Values:
    return [
        len(cast(Sized, pkt)) for pkt in pkts
    ]  # TODO fix Pkt to be a proper subtype of Sized


def concat_outputs(out_stem_list, out_base, suffix_list):
    for suffix in suffix_list:
        try:
            combined = pd.concat(
                [pd.read_csv(f"{f}{suffix}", index_col=[0]) for f in out_stem_list],
                ignore_index=True,
            )
            combined.to_csv(f"{out_base}{suffix}", index_label="index")
        except:
            print(traceback.format_exc())


def reverse_fid(fid: FlowID) -> FlowID:
    return FlowID(fid.dip, fid.sip, fid.dport, fid.sport, fid.proto)


def pair_flows(flows: Flows) -> Iterable[Tuple[int, int]]:
    pairs = set()
    used = set()

    for idx, (fid, pkts) in enumerate(flows):
        if idx in used:
            continue

        # do TCP-basd flow pairing
        if fid[4] == 6:
            if get_syn([pkts[0]])[0]:
                for bwd_idx, (bwd_fid, bwd_pkts) in enumerate(flows[idx + 1 :]):
                    if (
                        bwd_idx not in used
                        and fid == reverse_fid(bwd_fid)
                        and get_synack([bwd_pkts[0]])[0]
                    ):
                        other_side = idx + bwd_idx + 1
                        pairs.add((idx, other_side))
                        used.add(other_side)
                        break

        elif fid[4] == 17:
            for bwd_idx, (bwd_fid, bwd_pkts) in enumerate(flows[idx + 1 :]):
                if bwd_idx not in used and fid == reverse_fid(bwd_fid):
                    other_side = idx + bwd_idx + 1
                    pairs.add((idx, other_side))
                    used.add(other_side)
                    break

    return pairs


def interweave_flows(flows: List[Tuple[FlowID, List[Pkt]]], max_packets: int = -1):
    flow_pairs = pair_flows(flows)
    new_flows = []
    for fwd_idx, bwd_idx in flow_pairs:
        woven = sorted(flows[fwd_idx][1] + flows[bwd_idx][1], key=lambda pkt: pkt.time)[
            :max_packets
        ]
        new_flows.append((flows[fwd_idx][0], woven))

    return new_flows


def find_proxy(flows):
    """
    Find the proxy based on outgoing flows from the SS source port
    """
    fives = [flow[0] for flow in flows]
    sip_with_ss_sport = [tup[SIP] for tup in fives if tup[SPORT] == SS_PORT]
    counts = Counter(sip_with_ss_sport)
    if len(counts) > 1:
        print(f"WARNING more than 1 IP using {SS_PORT}: {counts}")
    return sorted(counts)[0]


def find_client(flows, proxy_ip):
    """
    Find the client based on outgoing flows to the SS dest port
    """
    fives = [flow[0] for flow in flows]
    sip = [tup[SIP] for tup in fives if tup[DIP] == proxy_ip and tup[DPORT] == SS_PORT]
    counts = Counter(sip)
    if len(counts) > 1:
        print(f"WARNING more than 1 IP using {SS_PORT}: {counts}")
    return sorted(counts)[0]


def get_flow_lengths(sizes):
    lengths = [len(s) for s in sizes]
    return min(lengths), max(lengths), Counter(lengths)


def main(cli_args):
    if type(cli_args.labeling) is not list:
        cli_args.labeling = cli_args.labeling.split(",")

    pcap_file = cli_args.pcap_file
    out_path, out_file = os.path.split(cli_args.out_file)
    out_stem = os.path.splitext(out_file)[0]

    suffix_list = []  # list of file suffixes to expect based on processing specified
    if cli_args.features != "":
        suffix_list.append(".csv")  # triggers outputting feature data




        # TODO: this mess works for now. Man, Python is the worst. Probably move this to
        # mice_base.Features. And of course, clean it up. Maybe test it?
        FEATURES_PACKAGE_NAME = "mice_base.Features"
        def filter_classes(cls):
            # if inspect.isclass(cls):
            # print(f"{cls.__module__ if hasattr(cls, '__module__') else cls} {inspect.ismodule(cls)}")
            return (
                inspect.isclass(cls)
                and not inspect.isabstract(cls)
                and str(cls.__module__).startswith("mice_base")
                # and cls.__module__ == FEATURES_PACKAGE_NAME
                and not issubclass(cls, PerPacketFeature)
                and issubclass(cls, ABC)
            )
        
        def get_features_from_package(packages) -> Dict[Any, Any]:
            features = []
            for package in packages:
                features.extend(inspect.getmembers(package, filter_classes))
            
            return dict(sorted(features, key=lambda x: x[0]))

        # feature_map = dict(
        #     sorted(inspect.getmembers(Features, filter_classes), key=lambda x: x[0])
        # )
        # feature_map = dict(
        #     sorted(inspect.getmembers(mice_base.BaseFeatures, filter_classes), key=lambda x: x[0])
        # )
        # feature_map = get_features_from_package(Features)
        feature_map = get_features_from_package([mice_base])
        
        
        # feature_map = get_features_from_package([Features, mice_base.DerivedFeatures.IATs])



        # feature_map = get_features_from_package([mice_base.BaseFeatures.Directions, mice_base.DerivedFeatures.IATs])
        # feature_map = get_features_from_package(mice_base.DerivedFeatures.DirSignSizes)
        # feature_map = get_features_from_package(mice_base.BaseFeatures.Directions)
        if len(feature_map) == 0:
            print(f"ERROR: failed to find ANY features in {FEATURES_PACKAGE_NAME}")
            exit(1)
            




        if cli_args.features == "all":
            cli_args.features = feature_map.values()
            print(f"using all {len(cli_args.features)} features: {list(feature_map.keys())}")
        else:
            feature_strings = cli_args.features.split(",")
            for name in feature_strings:
                if name not in feature_map:
                    print(
                        f"{name} not recognized as a Feature, check Features.py for names of Features"
                    )
                    print(f"These features are supported: ")
                    for feature in feature_map:
                        print(feature)
                    exit()

            feature_classes = []
            for name, cls in feature_map.items():
                if name in feature_strings:
                    feature_classes.append(cls)

            cli_args.features = feature_classes

    if "forward" in cli_args.labeling:
        suffix_list.append("_fwd_labels.csv")
    if "backward" in cli_args.labeling:
        suffix_list.append("_bwd_labels.csv")
    if "both" in cli_args.labeling or cli_args.unpaired:
        suffix_list.append("_both_labels.csv")

    try:
        run(pcap_file, cli_args)
    except:
        print(traceback.format_exc())


def run(pcap_file, cli_args):
    output = cli_args.out_file

    PROXIES = cli_args.proxies.split(",")
    CLIENTS = cli_args.clients.split(",")
    BACKGROUND = cli_args.known_background.split(",")

    max_packets = (
        (cli_args.win_count - 1) * cli_args.win_packets_slide
    ) + cli_args.win_packets
    flows = nmlp._pcap2flows(
        pcap_file, flow_pkts_thres=2, verbose=4, max_packets=max_packets
    )

    if cli_args.labeling:
        if len(PROXIES) == 0:
            PROXIES = [find_proxy(flows)]
        if len(CLIENTS) == 0:
            CLIENTS = [find_client(flows, PROXIES)]

    # allow relabeling without reprocessing features

    if not cli_args.unpaired:
        flows = interweave_flows(flows, max_packets)
    if cli_args.max_flows > 0:
        max_flows = flows[: cli_args.max_flows]
        del flows
        flows = max_flows

    if len(cli_args.features) > 0:
        win_config = win.Config(
            cli_args.win_packets,
            cli_args.win_count,
            cli_args.win_packets_slide,
            cli_args.features,
            cli_args.max_flows,
        )
        df = win.to_dataframe(win.process_flows(flows, win_config))

        df[[col for col in df if col != "flowid"]].to_csv(
            f"{output}.csv", index_label="index"
        )

    if not cli_args.unpaired or "both" in cli_args.labeling:
        labels = labeling.label_both(flows, CLIENTS, PROXIES)
        labels.to_csv(f"{output}_labels.csv", index_label="index")

    if "snowflake" in cli_args.labeling:
        labels = labeling.label_snowflake(flows, CLIENTS, BACKGROUND)
        labels.to_csv(f"{output}_labels.csv", index_label="index")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--pcap",
        dest="pcap_file",
        help="PCAP filename to process",
        required=True,
        type=str,
    )
    parser.add_argument(
        "--label",
        dest="labeling",
        help="forward, backward, both",
        required=False,
        default="",
        type=str,
    )
    parser.add_argument(
        "--features",
        dest="features",
        help="Comma-separated list of feature names",
        required=False,
        default="",
        type=str,
    )
    parser.add_argument(
        "--out", dest="out_file", help="Path to output file", required=True, type=str
    )
    parser.add_argument(
        "--proxies",
        dest="proxies",
        help="IP addresses of the proxies",
        required=False,
        default="",
        type=str,
    )
    parser.add_argument(
        "--known-background",
        dest="known_background",
        help="IP addresses of known background IPs (for labeling circumvention with unknown proxies)",
        required=False,
        default="",
        type=str,
    )
    parser.add_argument(
        "--clients",
        dest="clients",
        help="IP addresses of the clients",
        required=False,
        default="",
        type=str,
    )
    # parser.add_argument("--win-time",
    #                     dest="win_time",
    #                     help="Size of time window (excludes --win-packets)",
    #                     required=False,
    #                     default=0,
    #                     type=float)
    parser.add_argument(
        "--win-packets",
        dest="win_packets",
        help="Packets of packet window (excludes --win-time)",
        required=False,
        default=10,
        type=int,
    )
    # parser.add_argument("--win-time-slide",
    #                     dest="win_time_slide",
    #                     help="How far the time window slides (excludes --win-packets-slide)",
    #                     required=False,
    #                     default=0,
    #                     type=float)
    parser.add_argument(
        "--win-packets-slide",
        dest="win_packets_slide",
        help="How far the packets window slides (excludes --win-time-slide)",
        required=False,
        default=10,
        type=int,
    )
    parser.add_argument(
        "--win-count",
        dest="win_count",
        help="How many windows to incorporate",
        required=False,
        default=1,
        type=int,
    )
    # parser.add_argument("--win-time-start",
    #                     dest="win_time_start",
    #                     help="Where to start the windowing in time (excludes --win-time-start)",
    #                     required=False,
    #                     default=0,
    #                     type=float)
    parser.add_argument(
        "--win-packets-start",
        dest="win_packets_start",
        help="Where to start the windowing in packets (excludes --win-packets-start)",
        required=False,
        default=0,
        type=int,
    )
    parser.add_argument(
        "--unpaired",
        dest="unpaired",
        help="Do not pair the two directions of a flow, reverse direction features will be default-valued",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "--max-flows",
        dest="max_flows",
        help="Max number of flows to extract",
        required=False,
        default=0,
        type=int,
    )

    cli_args = parser.parse_args()
    main(cli_args)
