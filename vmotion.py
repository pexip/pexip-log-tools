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

"""
Analyze a Pexip MCU snapshot to determine if the machine was vMotioned

"""
import sys
import os
import os.path
import json
import re

USAGE = """%s [EXTRACTED_SNAPSHOT_PATH]""" % sys.argv[0]

RE_PARSE_VMSESSION_LINE = re.compile('(?P<timestamp>\d+-\d+-\d+T\d+:\d+:\d+)\.[0-9+:]+ (?P<host>\S+) (root|pexcrash).*Module="vmsessionid"\^M(?P<session_id>\S+)')

def check_version(snapshot_path):
    if os.path.exists(os.path.join(snapshot_path, 'opt/pexip/lib/python2.7/site-packages/si/web/management/conf/static/version.json')):
        version_file = os.path.join(snapshot_path, 'opt/pexip/lib/python2.7/site-packages/si/web/management/conf/static/version.json')
    else:
        version_file = os.path.join(snapshot_path, 'opt/pexip/share/web/static/version/version.json')

    if os.path.exists(version_file):
        with open(version_file, "r") as fh:
            version_json = fh.read()
    else:
        print("Error: version.json could not be found")
        sys.exit(2)

    version_info = json.loads(version_json)
    if version_info["major"] < 14:
        print("The ability to detect vMotion was added in v14.  Please run this against a snapshot of a v14 or higher deployment")
        sys.exit(1)

def get_ordered_list_of_osstatus_logs(snapshot_path):
    ordered_logs = {}
    num_files = 0
    log_dir_path = os.path.join(snapshot_path, "var", "log")
    for file_name in os.listdir(log_dir_path):
        if file_name.startswith("unified_osstatus.log") or file_name.startswith("osstatus.log"):
            extension = os.path.splitext(file_name)[1].replace(".", "")
            if extension == "log":
                extension = 0

            order_id = int(extension)
            ordered_logs[order_id] = os.path.join(log_dir_path, file_name)
            if order_id > num_files:
                num_files = order_id

    return (ordered_logs, num_files)


def scan_osstatus_logs(snapshot_path):
    vm_session_ids = {}
    vmotions_found = []
    (ordered_logs, num_files) = get_ordered_list_of_osstatus_logs(snapshot_path)
    for i in range(num_files, -1, -1):
        if i in ordered_logs:
            #print ordered_logs[i]
            with open(ordered_logs[i], 'r') as osstatus_log:
                for line in osstatus_log.readlines():
                    if 'Module="vmsessionid"' in line:
                        mo = RE_PARSE_VMSESSION_LINE.search(line)
                        host = mo.group('host')
                        vmsessionid = mo.group('session_id')
                        timestamp = mo.group('timestamp')
                        if host in vm_session_ids:
                            if vm_session_ids[host][0] != vmsessionid:
                                msg = "%s was vMotioned at sometime between %s and %s" % (host, vm_session_ids[host][1], timestamp)
                                vmotions_found.append(msg)
                                #print "\n\n**********************\n"
                                #print msg
                                #print "\n**********************\n\n"
                                #num_vmotions_found += 1
                        vm_session_ids[host] = (vmsessionid, timestamp)

    print("\n\nSUMMARY:\n")
    print("Hosts found:\n")
    for host in vm_session_ids:
        print("    %s" % host)
    print("\n")
    if not vmotions_found:
        print("No signs of any hosts being vMotioned")
    else:
        print("vMotion events found:\n")
        print("    %s" % "\n    ".join(vmotions_found))
    print("\n\n")




def main(snapshot_path):
    check_version(snapshot_path)
    scan_osstatus_logs(snapshot_path)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(USAGE)
        sys.exit(1)

    snapshot_path = sys.argv[1]

    if not os.path.exists(snapshot_path):
        print("'%s' does not exist" % snapshot_path)
        sys.exit(1)

    if not os.path.isdir(snapshot_path):
        print("'%s' is not a directory" % snapshot_path)
        sys.exit(1)

    main(snapshot_path)
