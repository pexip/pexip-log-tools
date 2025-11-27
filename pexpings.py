#!/usr/bin/env python3

# Copyright 2025 Pexip AS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Checks for irregular pings in unified_developer.log*

import fileinput
import glob
import os
import re
import sys

def main(rootdir):

    files = sorted(glob.glob(os.path.join(rootdir, 'var/log/unified_developer.log*')), key=os.path.getmtime, reverse=True)

    if files:
        capture = re.compile(r'(\d+-\d+-\d+T\d+:\d+:\d+\.\d+\+\d+:\d+)\s(\w+).+Irregular ping detected\s\((\d+\.\d+)\ssec\)\sin\s(\w+)\sprocess')
        irregularpings = False
        irregularping_timestamps = []
        irregularping_nodes = []
        irregularping_duration = []
        irregularping_process = []
        for line in fileinput.input(files):
            m = capture.search(line)
            if m:
                irregularpings = True
                irregularping_timestamps.append(m.group(1))
                irregularping_nodes.append(m.group(2))
                irregularping_duration.append(float(m.group(3)))
                irregularping_process.append(m.group(4))
        if irregularpings:
            print('Irregular ping report')
            print('=====================')
            print()
            # Table header
            print('Summary irregular ping entries')
            print()
            print('{:<10}{:<15}{:<20}{:<20}{:<20}'.format(
                'Node', 'Total Pings', 'Min Duration (sec)', 'Max Duration (sec)', 'Average Duration (sec)'
            ))
            print('-------------------------------------------------------------------------------')
            node_stats = []
            for node in set(irregularping_nodes):
                total_pings = irregularping_nodes.count(node)
                durations = [irregularping_duration[i] for i in range(len(irregularping_nodes)) if irregularping_nodes[i] == node]
                max_duration = max(durations)
                min_duration = min(durations)
                average_duration = sum(durations) / total_pings
                node_stats.append((node, total_pings, max_duration, min_duration, average_duration))
            # Sort by total_pings descending
            node_stats.sort(key=lambda x: x[1], reverse=True)
            for node, total_pings, max_duration, min_duration, average_duration in node_stats:
                print('{:<10}{:<15}{:<20.6f}{:<20.6f}{:<20.6f}'.format(
                    node, total_pings, min_duration, max_duration, average_duration
                ))
            print()
            print('Detailed irregular ping entries\n')
            print('{:<30}{:<10}{:<16}{:<15}'.format('Timestamp', 'Node', 'Duration (sec)', 'Process'))
            print('---------------------------------------------------------------')
            # Sort entries by timestamp ascending
            entries = list(zip(irregularping_timestamps, irregularping_nodes, irregularping_duration, irregularping_process))
            entries.sort(key=lambda x: x[0], reverse=False)
            for timestamp, node, duration, process in entries:
                print('{:<30}{:<10}{:<16.6f}{:<15}'.format(timestamp, node, duration, process))
            print()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        rootdir = sys.argv[1]
    else:
        rootdir = os.getcwd()
    try:
        if os.path.isdir(rootdir):
            main(rootdir)
        else:
            print('Usage: %s <snapshot folder>' % (os.path.basename(__file__)))
    except (IOError, KeyboardInterrupt):
        print('Usage: %s <snapshot folder>' % (os.path.basename(__file__)))
        pass
