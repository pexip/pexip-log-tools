#!/usr/bin/env python3
"""confhistory: extract conference history database into text format."""

# Copyright 2023 Pexip AS
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

import argparse
from datetime import datetime
import itertools
import os
import sqlite3
import sys

import locale
try:
    locale.setlocale(locale.LC_ALL, 'en_US')
except Exception:
    pass


def tabulate(data):
    """Tabulate data - data is an array (rows) or arrays (columns)"""
    lengths = [0] * len(data[0])
    for row in data:
        for ind in range(len(row)):
            if len(str(row[ind])) > lengths[ind]:
                lengths[ind] = len(str(row[ind]))
    for row in data:
        for ind in range(len(row)):
            print(str(row[ind]), end=" ")
            print(" " * (lengths[ind] - len(str(row[ind]))), end=" ")
        print()

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def parse_args(argv=None):
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Extract conference history database into text format')
    parser.add_argument('rootdir', nargs='?', default=os.getcwd(), help='Root directory under which to find databases (default: current directory)')
    parser.add_argument('--conf', help='Conference name or uuid to search for')
    parser.add_argument('--show-backplanes', action='store_true', help='Show backplane information')
    return parser.parse_args(argv)


class ConfHistory:
    def __init__(self, rootdir):
        def connect_db(db_path, label, row_factory):
            if not os.path.isfile(db_path):
                raise FileNotFoundError(f"{label} database not found: {db_path}")
            try:
                conn = sqlite3.connect(db_path)
            except sqlite3.Error as exc:
                raise RuntimeError(f"Unable to open {label} database: {db_path} ({exc})") from exc
            conn.row_factory = row_factory
            return conn

        config_path = os.path.join(rootdir, 'opt/pexip/share/config/conferencing_configuration.db')
        self.config = connect_db(config_path, 'config', sqlite3.Row)

        if os.path.isdir(os.path.join(rootdir, 'opt/pexip/share/status/db')):
            status_path = os.path.join(rootdir, 'opt/pexip/share/status/db/conferencing_status.db')
        else:
            status_path = os.path.join(rootdir, 'opt/pexip/share/status/conferencing_status.db')
        self.status = connect_db(status_path, 'status', dict_factory)

        history_path = os.path.join(rootdir, 'opt/pexip/share/history/conferencing_history.db')
        self.history = connect_db(history_path, 'history', dict_factory)
        self.nodes = {}
        self.locations = {}
        self._get_nodes()

    def _get_nodes(self):
        cur = self.config.cursor()
        cur.execute("SELECT platform_workervm.address, platform_workervm.name, platform_systemlocation.name FROM platform_workervm LEFT JOIN  platform_systemlocation ON platform_workervm.system_location_id=platform_systemlocation.id")
        for row in cur:
            #ret[row[0]] = {'name': row[1], 'location': row[2]}
            self.nodes[row[0]] = row[1]
            self.locations[row[0]] = row[2]

    def backplanes(self, c_uuid=None):
        backplanes = {}
        cur = self.history.cursor()
        cur.execute('SELECT id, type, media_node, remote_media_node, proxy_node, start_time, end_time, duration FROM conferencinghistory_backplane WHERE conference_id=?', (c_uuid,))
        rows = cur.fetchall()
        headers = ['id', 'type', 'media_node', 'remote_media_node', 'proxy_node', 'start_time', 'end_time', 'duration']
        data = [headers]
        if not rows:
            return
        else:
            print("Backplanes")
            print(len("Backplanes") * "=")
            for row in rows:
                backplanes[row['id']] = row
                data.append([row['id'], row['type'], row['media_node'], row['remote_media_node'], row['proxy_node'] if row['proxy_node'] else 'None', row['start_time'], row['end_time'], row['duration']])
            tabulate(data)
        if rows:
            print()
            for row in rows:
                cur2 = self.history.cursor()
                cur2.execute('SELECT backplane_id, stream_type, tx_codec, tx_resolution, tx_bitrate, tx_packets_sent, tx_packets_lost, rx_codec, rx_resolution, rx_bitrate, rx_packets_received, rx_packets_lost from conferencinghistory_backplanemediastream where backplane_id=?', (row['id'],))
                rows = cur2.fetchall()
                stats = [['', 'tx_codec', 'tx_resolution', 'tx_bitrate', 'tx_packets_sent', 'tx_packets_lost', 'rx_codec', 'rx_resolution', 'rx_bitrate', 'rx_packets_received', 'rx_packets_lost']]
                backplane_id = ''
                for row in rows:
                    backplane_id = row['backplane_id']
                    stats.append([
                        row['stream_type'],
                        row['tx_codec'],
                        row['tx_resolution'],
                        row['tx_bitrate'],
                        row['tx_packets_sent'],
                        row['tx_packets_lost'],
                        row['rx_codec'],
                        row['rx_resolution'],
                        row['rx_bitrate'],
                        row['rx_packets_received'],
                        row['rx_packets_lost'],
                    ])
                if not rows:
                    continue
                print(backplane_id)
                tabulate(stats)
                print()

    def participants(self, c_uuid=None, c_name=None, c_start=None):
        participant_count = {}
        cur = self.history.cursor()
        if c_start and c_name:
            cur.execute('SELECT * from conferencinghistory_participant WHERE conference_id IS NULL AND conference_name=? AND start_time > ? ORDER BY start_time', (c_name, c_start))
            cur2 = self.status.cursor()
            cur2.execute('SELECT * from conferencingstatus_participant WHERE conference=? ORDER BY connect_time', (c_name,))
            itercur = itertools.chain(cur, cur2)
        else:
            cur.execute('SELECT * from conferencinghistory_participant WHERE conference_id=? ORDER BY start_time', (c_uuid,))
            itercur = cur

        for row in itercur:
            start_ts = None
            end_ts = None
            connect_ts = None # Status only

            if 'connect_time' in row and row['connect_time']:
                connect_ts = row['connect_time'].split('.', 1)[0]
                if connect_ts in participant_count:
                    participant_count[connect_ts] += 1
                else:
                    participant_count[connect_ts] = 1
            if 'end_time' in row and row['end_time']:
                end_ts = row['end_time'].split('.', 1)[0]
            if 'start_time' in row and row['start_time']:
                start_ts = row['start_time'].split('.', 1)[0]
                if start_ts in participant_count:
                    participant_count[start_ts] += 1
                else:
                    participant_count[start_ts] = 1
                if end_ts in participant_count:
                    participant_count[end_ts] -= 1
                else:
                    participant_count[end_ts] = -1

            print()

            if connect_ts:
                print("%s <%s> (%s) / %s" % (row['display_name'], row['source_alias'], row['protocol'], row['role']))
                print("Call-ID: %s" % row['call_uuid'])
                print("Participant-ID: %s" % row['id'])
                print("Remote Address: %s" % row['remote_address'])
                print("Start: %s / STILL CONNECTED" % connect_ts)
            else:
                print("%s <%s> (%s) / %s" % (row['display_name'], row.get('remote_alias', ''), row['protocol'], row['role']))
                print("Call-ID: %s" % row['call_uuid'])
                print("Participant-ID: %s" % row['id'])
                print("Remote Address: %s" % row['remote_address'])
                if start_ts:
                    print("Start: %s / End: %s / Duration: %s" % (start_ts, end_ts, (datetime.strptime(end_ts, "%Y-%m-%d %H:%M:%S") - datetime.strptime(start_ts, "%Y-%m-%d %H:%M:%S"))))
                else:
                    print("FAILED CALL / End: %s" % end_ts)
                print("Disconnect Reason: %s" % row.get('disconnect_reason', ''))

            if row.get("external_node_id"):
                print("External-Node-ID: %s" % row['external_node_id'])
            print("Remote Vendor: %s" % row['vendor'])
            print("Media Node: %s [%s, %s] / Signalling Node: %s [%s, %s]" % (row['media_node'], self.nodes.get(row['media_node'], "Unknown"), self.locations.get(row['media_node'], "Unknown"), row['signalling_node'], self.nodes.get(row['signalling_node'], "Unknown"), self.locations.get(row['signalling_node'], "Unknown")), end="")
            if (row['proxy_node']):
                print(" / Proxy Node: %s [%s, %s]" % (row['proxy_node'], self.nodes.get(row['proxy_node'], "Unknown"), self.locations.get(row['proxy_node'], "Unknown")), end="")
            print()
            print()

            if start_ts:
                cur2 = self.history.cursor()
                cur2.execute('SELECT * from conferencinghistory_participantmediastream WHERE participant_id=?', (row['id'],))
                stats = [['', 'tx_codec', 'tx_resolution', 'tx_bitrate', 'tx_packets_sent', 'tx_packets_lost', 'rx_codec', 'rx_resolution', 'rx_bitrate', 'rx_packets_received', 'rx_packets_lost']]
                for row in cur2:
                    stats.append([
                        row.get('stream_type', ''),
                        row.get('tx_codec', ''),
                        row.get('tx_resolution', ''),
                        row.get('tx_bitrate', ''),
                        row.get('tx_packets_sent', ''),
                        row.get('tx_packets_lost', ''),
                        row.get('rx_codec', ''),
                        row.get('rx_resolution', ''),
                        row.get('rx_bitrate', ''),
                        row.get('rx_packets_received', ''),
                        row.get('rx_packets_lost', ''),
                    ])
                tabulate(stats)
                print()

        if participant_count:
            prev_ts = None
            for ts in sorted(participant_count.keys()):
                if prev_ts:
                    participant_count[ts] += participant_count[prev_ts]
                prev_ts = ts

            peak_participants = "Peak participants: %d" % max(participant_count.values())
            print(peak_participants)

    def conferences_history(self, conf, show_backplanes=False):
        cur = self.history.cursor()
        if conf:
            cur.execute('SELECT * from conferencinghistory_conference WHERE name LIKE ? OR id = ? ORDER BY start_time', ('%' + conf + '%', conf))
        else:
            cur.execute('SELECT * FROM conferencinghistory_conference ORDER BY start_time')

        for row in cur:
            times = "Start: %s / End: %s" % (row['start_time'], row['end_time'])
            print("=" * len(times))
            print(row['name'])
            print("Conference ID:", row['id'])
            print(times)
            print("-" * len(times))
            self.participants(c_uuid=row['id'])
            if show_backplanes:
                print()
                self.backplanes(c_uuid=row['id'])
                print()

    def conferences_status(self, conf):
        cur = self.status.cursor()
        if conf:
            cur.execute('SELECT * from conferencingstatus_conference WHERE name LIKE ? OR id = ? ORDER BY start_time', ('%' + conf + '%', conf))
        else:
            cur.execute('SELECT * FROM conferencingstatus_conference ORDER BY start_time')

        for row in cur:
            times = "Start: %s / STILL RUNNING" % (row['start_time'],)
            print("=" * len(times))
            print(row['name'])
            print(times)
            print("-" * len(times))
            self.participants(c_name=row['name'], c_start=row['start_time'])
            print()


def main():
    """Main processing - rootdir is /opt/pexip/share equivalent under which databases lie"""
    args = parse_args()
    try:
        dba = ConfHistory(args.rootdir)
        dba.conferences_history(args.conf, show_backplanes=args.show_backplanes)
        dba.conferences_status(args.conf)
    except (FileNotFoundError, RuntimeError, sqlite3.Error) as exc:
        print(f"Error: {exc}", file=sys.stderr, flush=True)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
