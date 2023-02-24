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
import itertools as it
import os
import shutil
import subprocess
import traceback
import typing
from collections import Counter
from functools import reduce
from statistics import mean, median, stdev

import numpy as np
import pandas as pd
import scapy
import seaborn as sn
from pandas import DataFrame
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scipy.stats import entropy

import netml_parser as nmlp
import netml_tools as nmlt
from mice_base.fe_types import FlowID, Pkt, Pkts, Feature, Window
from mice_base.BaseFeatures.WindowFeature import window_name

from typing import Iterable

VALUE_ORDER = [
    # "stats",
    "ACK",
    "PSH",
    "URG",
    "entropy",
    "iat",
    "size",
]


def _entropy_helper(pkt: Pkt, end=-1, begin=0, layer=scapy.all.Raw) -> float:
    if not pkt.haslayer(layer):
        return 0.0

    pk = list(Counter(pkt.payload[layer].original[begin:end]).values())
    return entropy(pk, base=2)


def flatten_window(window: str, features: Iterable[Any]) -> Iterable[Any]:
# def flatten_window(window: str, features: Iterable[Feature]) -> Iterable[Feature]:
    return [(window_name(window, name), data) for name, data in features]


def get_feature_names(config) -> List[str]:
    features = []
    for win_idx in range(config.win_num):
        for feature in config.features:
            features += [
                window_name(f"w{win_idx}", name)
                for name in feature.get_names(config.win_size)
            ]

    return features


def extract_flow(features: Iterable[Callable], windows: Iterable[Window]) -> np.ndarray:
    window_features: List[Tuple[str, Iterable[Feature]]] = []
    for window in windows:
        size = window.end - window.start
        window_features.append(
            it.chain(
                *[
                    feature.get_value(window.fid, window.data, size)
                    for feature in features
                ]
            ),
        )
    return np.array(list(it.chain(*[data for data in window_features])))


def construct_pkt_windows(
    pkts: List[Pkt],
    fid: FlowID,
    size: int,
    number: int,
    slide: int,
) -> Iterable[Window]:
    windows = []
    start = 0
    for idx in range(number):
        pktSlice = Pkts(f"{fid}-w{idx}", pkts[start : start + size])
        windows.append(Window(f"w{idx}", start, start + size, fid, pktSlice))
        start += slide

    return windows


def construct_time_windows(
    pkts: Pkts, size: int, number: int, slide: int
) -> Iterable[Window]:
    pass


class Config(NamedTuple):
    win_size: int
    win_num: int
    win_slide: int
    features: Iterable[Callable]
    max_flows: int


def process_flows(
    flows: Iterable[Tuple[FlowID, List[Pkt]]], config: Config
) -> Iterable[Tuple[FlowID, Iterable[Feature]]]:
    extracted: List[Tuple[FlowID, Iterable[Feature]]] = []
    fid_list = []
    for fid, pktsList in flows:
        windows = construct_pkt_windows(
            pktsList, fid, config.win_size, config.win_num, config.win_slide
        )
        extracted.append(extract_flow(config.features, windows))
        fid_list.append(fid)
        if len(extracted) % 1000 == 0:
            print(f"Flows Extracted: {len(extracted)}")

        if config.max_flows and len(extracted) >= config.max_flows:
            break

    return get_feature_names(config), fid_list, extracted


def to_dataframe(features_fids_data: Iterable[Tuple[FlowID, Iterable[Feature]]]) -> DataFrame:
    features, fids, data = features_fids_data
    df = DataFrame(data, columns=features)
    df["FlowID"] = fids
    df = df[["FlowID"] + features]
    print(df)
    return df


def main(cli_args):
    pass


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
        "--out", dest="out_file", help="Path to output file", required=True, type=str
    )
    parser.add_argument(
        "--split",
        dest="split",
        help="Split files larger than this many megabytes",
        required=False,
        default=1000,
        type=int,
    )
    cli_args = parser.parse_args()
    main(cli_args)
