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
import statistics
import sys

idle_threshold = 0.38

def main(rootdir):

    files = sorted(glob.glob(os.path.join(rootdir, 'var/log/unified_developer.log*')), key=os.path.getmtime, reverse=True)

    if files:
        worker_load_capture = re.compile(r'(\d+-\d+-\d+T\d+:\d+:\d+\.\d+\+\d+:\d+)\s([\w.\-_]+).+"worker_load_monitor".+Media\sCPU\sload:\s(\d+\.\d+),\sAvg\ssystem\sidle:\s(\d+\.\d+),\sInstant\ssystem\sidle:\s(\d+\.\d+),\sNUMA:\s\[(\d+\.\d+(,\s\d+\.\d+)?)\]')
        irregular_ping_capture = re.compile(r'(\d+-\d+-\d+T\d+:\d+:\d+\.\d+\+\d+:\d+)\s([\w.\-_]+).+Irregular ping detected\s\((\d+\.\d+)\ssec\)\sin\s(\w+)\sprocess')
        irregular_pulse_capture = re.compile(r'(\d+-\d+-\d+T\d+:\d+:\d+\.\d+\+\d+:\d+)\s([\w.\-_]+).+"Irregular pulse duration detected"\sDuration="(\d+\.\d+)"')
        multiple_numa_detected = False
        multiple_numa_nodes = []
        load_timestamps = []
        load_nodes = []
        loads_media_cpu = []
        #loads_avg_system_idle = []
        loads_instant_system_idle = []
        loads_numa = []
        load_below_threshold_timestamps = []
        load_below_threshold_nodes = []
        load_below_threshold_values = []
        irregularpings = False
        irregularping_timestamps = []
        irregularping_nodes = []
        irregularping_duration = []
        irregularping_process = []
        irregularpulse = False
        irregularpulse_timestamps = []
        irregularpulse_nodes = []
        irregularpulse_duration = []
        for line in fileinput.input(files):
            load_match = worker_load_capture.search(line)
            if load_match:
                load_timestamps.append(load_match.group(1))
                load_nodes.append(load_match.group(2))
                loads_media_cpu.append(float(load_match.group(3)))
                #loads_avg_system_idle.append(float(load_match.group(4)))
                loads_instant_system_idle.append(float(load_match.group(5)))
                try:
                    loads_numa.append(float(load_match.group(6)))
                except ValueError:
                    # Multiple NUMA values, take average and flag
                    numa_values = [float(x) for x in load_match.group(6).split(', ')]
                    loads_numa.append(statistics.mean(numa_values))
                    multiple_numa_detected = True
                    multiple_numa_nodes.append(load_match.group(2))
                # Check for instant system idle below threshold
                if float(load_match.group(5)) < float(idle_threshold):
                    load_below_threshold_timestamps.append(load_match.group(1))
                    load_below_threshold_nodes.append(load_match.group(2))
                    load_below_threshold_values.append(float(load_match.group(5)))
            irregular_ping_match = irregular_ping_capture.search(line)
            if irregular_ping_match:
                irregularpings = True
                irregularping_timestamps.append(irregular_ping_match.group(1))
                irregularping_nodes.append(irregular_ping_match.group(2))
                irregularping_duration.append(float(irregular_ping_match.group(3)))
                irregularping_process.append(irregular_ping_match.group(4))
            irregular_pulse_match = irregular_pulse_capture.search(line)
            if irregular_pulse_match:
                irregularpulse = True
                irregularpulse_timestamps.append(irregular_pulse_match.group(1))
                irregularpulse_nodes.append(irregular_pulse_match.group(2))
                irregularpulse_duration.append(float(irregular_pulse_match.group(3)))
        print('Stall report')
        print(len('Stall report') * '=')
        print()
        print('Irregular pulse entries: %d' % (len(irregularpulse_nodes)))
        print('Irregular ping entries: %d' % (len(irregularping_nodes)))
        print('Worker load monitor entries processed: %d' % (len(load_nodes)))
        print()
        if multiple_numa_detected:
            print('!!! Multiple NUMA node values detected; averages were used. !!!')
            print('Affected nodes: %s' % (", ".join(set(multiple_numa_nodes))))
        print()
        if load_nodes:
            print('{:<20}{:<25}{:<25}{:<25}{}'.format(
                'Node',
                'Media CPU load',
                'NUMA',
                'Instant system idle',
                'Instant idle timestamp (min)'
            ))
            print('{:<20}{:<25}{:<25}{:<25}{}'.format(
                '',
                '(min/max/avg)',
                '(min/max/avg)',
                '(min/max/avg)',
                ''
            ))
            print('-------------------------------------------------------------------------------------------------------------')
            node_stats = []
            for node in set(load_nodes):
                indices = [i for i in range(len(load_nodes)) if load_nodes[i] == node]
                media_cpu_vals = [loads_media_cpu[i] for i in indices]
                #avg_sys_idle_vals = [loads_avg_system_idle[i] for i in indices]
                inst_sys_idle_vals = [loads_instant_system_idle[i] for i in indices]
                numa_vals = [loads_numa[i] for i in indices]
                min_cpu = min(media_cpu_vals)
                max_cpu = max(media_cpu_vals)
                avg_cpu = statistics.mean(media_cpu_vals)
                # min_avg_idle = min(avg_sys_idle_vals)
                # max_avg_idle = max(avg_sys_idle_vals)
                # avg_avg_idle = statistics.mean(avg_sys_idle_vals)
                min_inst_idle = min(inst_sys_idle_vals)
                max_inst_idle = max(inst_sys_idle_vals)
                avg_inst_idle = statistics.mean(inst_sys_idle_vals)
                min_numa = min(numa_vals)
                max_numa = max(numa_vals)
                avg_numa = statistics.mean(numa_vals)
                node_timestamps = [load_timestamps[i] for i in indices]
                min_inst_idle_index = inst_sys_idle_vals.index(min_inst_idle)
                min_inst_idle_timestamp = node_timestamps[min_inst_idle_index]
                node_stats.append((
                    node,
                    (min_cpu, max_cpu, avg_cpu),
                    (min_numa, max_numa, avg_numa),
                    #(min_avg_idle, max_avg_idle, avg_avg_idle),
                    (min_inst_idle, max_inst_idle, avg_inst_idle),
                    min_inst_idle_timestamp
                ))
            # Sort by avg_cpu descending
            node_stats.sort(key=lambda x: x[1][2], reverse=True)
            for node, cpu_vals, numa_vals, inst_idle_vals, min_inst_idle_timestamp in node_stats:
                print('{:<20}{:.2f}/{:.2f}/{:<15.2f}{:.2f}/{:.2f}/{:<15.2f}{:.2f}/{:.2f}/{:<15.2f}{}'.format(
                    node,
                    cpu_vals[0], cpu_vals[1], cpu_vals[2],
                    numa_vals[0], numa_vals[1], numa_vals[2],
                    inst_idle_vals[0], inst_idle_vals[1], inst_idle_vals[2],
                    min_inst_idle_timestamp
                ))
            print()
        if load_below_threshold_nodes:
            print('Nodes with instant system idle below %.2f:' % (idle_threshold))
            print('{:<30}{:<20}{:<25}'.format('Timestamp', 'Node', 'Idle Value'))
            print('--------------------------------------------------------------')
            # Sort entries by timestamp ascending
            entries = list(zip(load_below_threshold_timestamps, load_below_threshold_nodes, load_below_threshold_values))
            entries.sort(key=lambda x: x[0], reverse=False)
            for timestamp, node, value in entries:
                print('{:<30}{:<20}{:<25.2f}'.format(timestamp, node, value))
            print()
        if irregularpulse:
            # Table header
            print()
            print('Irregular pulse')
            print(len('Irregular pulse') * '=')
            print()
            print('Summary of irregular pulses found')
            print('{:<20}{:<15}{:<20}{:<20}{:<20}'.format(
                'Node', 'Total Pulses', 'Min Duration (sec)', 'Max Duration (sec)', 'Average Duration (sec)'
            ))
            print('-------------------------------------------------------------------------------------------------')
            node_stats = []
            for node in set(irregularpulse_nodes):
                total_pulses = irregularpulse_nodes.count(node)
                durations = [irregularpulse_duration[i] for i in range(len(irregularpulse_nodes)) if irregularpulse_nodes[i] == node]
                max_duration = max(durations)
                min_duration = min(durations)
                average_duration = statistics.mean(durations)
                node_stats.append((node, total_pulses, max_duration, min_duration, average_duration))
            # Sort by total_pulses descending
            node_stats.sort(key=lambda x: x[1], reverse=True)
            for node, total_pulses, max_duration, min_duration, average_duration in node_stats:
                print('{:<20}{:<15}{:<20.6f}{:<20.6f}{:<20.6f}'.format(
                    node, total_pulses, min_duration, max_duration, average_duration
                ))
            print()
            print()
            print('Details of irregular pulses found')
            print('{:<30}{:<20}{:<16}'.format('Timestamp', 'Node', 'Duration (sec)'))
            print('----------------------------------------------------------------')
            # Sort entries by timestamp ascending
            entries = list(zip(irregularpulse_timestamps, irregularpulse_nodes, irregularpulse_duration))
            entries.sort(key=lambda x: x[0], reverse=False)
            for timestamp, node, duration in entries:
                print('{:<30}{:<20}{:<16.6f}'.format(timestamp, node, duration))
            print()
        if irregularpings:
            # Table header
            print()
            print('Irregular pings')
            print(len('Irregular pings') * '=')
            print()
            print('Summary of irregular pings found')
            print('{:<20}{:<15}{:<20}{:<20}{:<20}'.format(
                'Node', 'Total Pings', 'Min Duration (sec)', 'Max Duration (sec)', 'Average Duration (sec)'
            ))
            print('-------------------------------------------------------------------------------------------------')
            node_stats = []
            for node in set(irregularping_nodes):
                total_pings = irregularping_nodes.count(node)
                durations = [irregularping_duration[i] for i in range(len(irregularping_nodes)) if irregularping_nodes[i] == node]
                max_duration = max(durations)
                min_duration = min(durations)
                average_duration = statistics.mean(durations)
                node_stats.append((node, total_pings, max_duration, min_duration, average_duration))
            # Sort by total_pings descending
            node_stats.sort(key=lambda x: x[1], reverse=True)
            for node, total_pings, max_duration, min_duration, average_duration in node_stats:
                print('{:<20}{:<15}{:<20.6f}{:<20.6f}{:<20.6f}'.format(
                    node, total_pings, min_duration, max_duration, average_duration
                ))
            print()
            print()
            print('Details of irregular pings found')
            print('{:<30}{:<20}{:<16}{:<15}'.format('Timestamp', 'Node', 'Duration (sec)', 'Process'))
            print('-------------------------------------------------------------------------')
            # Sort entries by timestamp ascending
            entries = list(zip(irregularping_timestamps, irregularping_nodes, irregularping_duration, irregularping_process))
            entries.sort(key=lambda x: x[0], reverse=False)
            for timestamp, node, duration, process in entries:
                print('{:<30}{:<20}{:<16.6f}{:<15}'.format(timestamp, node, duration, process))
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
