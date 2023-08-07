#!/usr/bin/env python3
"""connectivity: process admin logs for connectivity loss events."""

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
import fileinput
import glob
import os
import re
import sqlite3
import sys

from datetime import datetime

quot_end = re.compile(r'"(?:\s+|$)')

def tokenize(stuff):
    fields = {}
    while '="' in stuff:
        equ = stuff.find('="')
        key = stuff[:equ]
        stuff = stuff[equ+2:]
        if stuff.startswith("^M"):
            stuff = stuff[2:]
            quot = -1
        else:
            loc = quot_end.search(stuff)
            quot = loc.start() if loc else -1
        value = stuff[:quot]
        fields[key] = value
        stuff = stuff[quot+2:]

    return fields

def main():
    parser = argparse.ArgumentParser(description="Parses admin logs to show connectivity issues")
    parser.add_argument("snapshot", metavar="DIR", nargs="?", help="directory of unpacked snapshot")
    parser.add_argument("--no-names", action="store_true", help="don't show node names")
    parser.add_argument("--consolidate", action="store_true", help="consolidate connectivity issues per location")
    args = parser.parse_args()

    rootdir = os.getcwd()
    show_names = not args.no_names
    consolidate = args.consolidate
    if args.snapshot and os.path.isdir(args.snapshot):
        rootdir = args.snapshot

    configuration = sqlite3.connect(os.path.join(rootdir, 'opt/pexip/share/config/conferencing_configuration.db'))
    configuration.row_factory = sqlite3.Row
    cur = configuration.cursor()
    cur.execute("SELECT platform_workervm.address, platform_workervm.hostname, platform_systemlocation.name FROM platform_workervm, platform_systemlocation WHERE platform_workervm.system_location_id==platform_systemlocation.id")
    locations = {}
    names = {}
    for row in cur:
        names[row[0]] = row[1]
        locations[row[0]] = row[2]
    cur.execute("SELECT address FROM platform_managementvm")
    for row in cur:
        names[row[0]] = "[Manager]"
        locations[row[0]] = "Manager"
    configuration.close()
    location_len = str(max([len(l) for l in locations.values()]))

    try:
        log_files = sorted(glob.glob(os.path.join(rootdir, 'var/log/*administrator.log*')), key=os.path.getmtime)
    except OSError as err:
        print(err)
        sys.exit(2)

    data = {}

    for line in fileinput.input(log_files, openhook=fileinput.hook_encoded("utf-8")):
        if "system.connectivity" not in line:
            continue

        line = line[30:]
        # line = 'us-mns-wrk1 2014-08-01 13:14:02,030 Level="INFO" ...'
        preamble = line.split(None, 3)
        host = preamble[0]
        tts = ' '.join(preamble[1:3])
        fields = tokenize(preamble[3])

        try:
            if consolidate:
                key = ("%" + location_len + "s -> %" + location_len + "s") % tuple(sorted((locations.get(fields["Node"]), locations.get(fields["Src-Node"]))))
            else:
                key = "%15s -> %15s" % (fields["Node"], fields["Src-Node"])
        except KeyError:
            print(line)
            continue

        if fields["Message"] == "Connectivity lost to node.":
            if "Last-Reported" in fields:
                data[key] = datetime.strptime(fields["Last-Reported"], "%a %b %d %H:%M:%S %Y")
            else:
                data[key] = datetime.strptime(tts[:19], "%Y-%m-%d %H:%M:%S")
        elif fields["Message"] == "Connectivity re-established." and (not consolidate or key in data):
            start = datetime.strptime(fields["Last-Reported"], "%a %b %d %H:%M:%S %Y")
            if consolidate:
                subkey = ""
            elif show_names:
                subkey = "%s [%s] -> %s [%s]" % (names.get(fields["Node"]), locations.get(fields["Node"]), names.get(fields["Src-Node"]), locations.get(fields["Src-Node"]))
            else:
                subkey = "%s -> %s" % (locations.get(fields["Node"]), locations.get(fields["Src-Node"]))
            print(fields["Last-Reported"], key, datetime.strptime(tts[:19], "%Y-%m-%d %H:%M:%S") - start, subkey)
            if key in data:
                del data[key]


if __name__ == "__main__":
    try:
        main()
    except (IOError, KeyboardInterrupt):
        pass
