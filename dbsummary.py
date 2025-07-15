#!/usr/bin/env python3
"""dbsummary: extract key configuraton information into text format."""

# Copyright 2024 Pexip AS
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

import copy
import json
import operator
import os
import re
import sqlite3
import sys
from datetime import datetime, timedelta

try:
    import dns.resolver
    do_dns = True
except ImportError:
    do_dns = False

import locale
try:
    locale.setlocale(locale.LC_ALL, 'en_US')
except Exception:
    pass

try:
    from cryptography import x509
    from cryptography.x509.general_name import (
        DNSName,
        IPAddress
    )
    do_ssl = True
except ImportError:
    do_ssl = False


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
        print("")


class SecurityCheck:
    def __init__(self, rootdir: str):
        self.json_file = os.path.join(rootdir, 'etc/pexip/security/security.json')
        if not os.path.exists(self.json_file):
            return None

    def _security_defaults(self) -> dict:
        """Return the default security settings.
        Should cover all settings from v30 onwards."""
        return {
            "cca_id": "",
            "disable_admin_account": False,
            "drop_not_reject": True,
            "enable_aes128_sha": False,
            "enable_fir": False,
            "enable_frame_deny": True,
            "enable_hsts_preload": False,
            "enable_referrer_policy": True,
            "enable_sip_aes128_sha": True,
            "enable_sip_tls_adh": False,
            "enable_sip_tls_cert_tolerate_ip_address": False,
            "enable_tls1": False,
            "enable_web_allowed_hosts_validation": False,
            "enable_worker_csp": False,
            "fips_mode": False,
            "icmpv6_echo_requests": True,
            "icmpv6_redirects": False,
            "ipv6_dad_transmits": True,
            "permit_https_old_tls": False,
            "require_encrypted_media": False,
            "resource_priority_prefix": "",
            "sip_tcp_port": 5060,
            "sip_tls_port": 5061,
            "sip_udp_port": 5060,
            "web_global_session_limit": None,
            "web_per_user_session_limit": None,
            "enable_srtp_hmac_sha1": True,
            "enable_tls12_cbc": True,
            "enable_h323_2048bit_dh": False
            }

    def read_security_json(self) -> dict | None:
        """Read the security.json file and check for any changes."""
        try:
            with open(self.json_file, 'r') as fh:
                data = json.load(fh)
        except (IOError, ValueError):
            return None

        if not isinstance(data, dict):
            return None

        defaults = self._security_defaults()
        changes = {}
        for key in data.keys():
            if key not in defaults:
                continue
            if data[key] != defaults[key]:
                if key not in changes:
                    changes[key] = data[key]

        return changes


class DBAnalyser:
    def __init__(self, rootdir):
        if os.path.isdir(os.path.join(rootdir, 'opt/pexip/share/status/db')):
            statusdir = os.path.join(rootdir, 'opt/pexip/share/status/db')
        else:
            statusdir = os.path.join(rootdir, 'opt/pexip/share/status')
        self.platform_status = sqlite3.connect(os.path.join(statusdir, 'platform_status.db'))
        self.platform_status.row_factory = sqlite3.Row
        self.conferencing_status = sqlite3.connect(os.path.join(statusdir, 'conferencing_status.db'))
        self.conferencing_status.row_factory = sqlite3.Row
        self.configuration = sqlite3.connect(os.path.join(rootdir, 'opt/pexip/share/config/conferencing_configuration.db'))
        self.configuration.row_factory = sqlite3.Row
#        self.history = sqlite3.connect(os.path.join(rootdir, 'opt/pexip/share/history/conferencing_history.db'))
#        self.history.row_factory = sqlite3.Row

        if os.path.exists(os.path.join(rootdir, 'opt/pexip/lib/python2.7/site-packages/si/web/management/conf/static/version.json')):
            self.version = json.load(open(os.path.join(rootdir, 'opt/pexip/lib/python2.7/site-packages/si/web/management/conf/static/version.json'), 'r'))
        else:
            self.version = json.load(open(os.path.join(rootdir, 'opt/pexip/share/web/static/version/version.json'), 'r'))

        try:
            if os.path.exists(os.path.join(rootdir, 'opt/pexip/share/status/licenses.json')):
                self.licenses = json.load(open(os.path.join(rootdir, 'opt/pexip/share/status/licenses.json'), 'r'))
            else:
                self.licenses = json.load(open(os.path.join(rootdir, 'etc/licenses.json'), 'r'))
        except (IOError, ValueError):
            self.licenses = {}

        self.certsdir = os.path.join(rootdir, 'opt/pexip/share/certs')

        self.cache = {}

        osstatus_file = os.path.join(rootdir, 'var/log/unified_osstatus.log')
        self.osstatus = {}  # hostname -> status
        start = None
        if os.path.exists(osstatus_file):
            start = 1
            osstatus_next = osstatus_file
        else:
            for ind in range(1, 150):
                osstatus_next = osstatus_file + '.' + str(ind)
                if os.path.exists(osstatus_next):
                    start = ind + 1
                    break

        if start is not None:
            self.osstatus = self._read_osstatus(osstatus_next)
            mtime = os.path.getmtime(osstatus_next) - 4200
            for ind in range(start, 150):
                osstatus_next = osstatus_file + '.' + str(ind)
                if not os.path.exists(osstatus_next) or os.path.getmtime(osstatus_next) < mtime:
                    break
                self._update_osstatus(self._read_osstatus(osstatus_next))

    def _update_osstatus(self, osstatus):
        for key in osstatus.keys():
            if key not in self.osstatus:
                self.osstatus[key] = osstatus[key]
            else:
                for key2 in osstatus[key].keys():
                    if key2 not in self.osstatus[key]:
                        self.osstatus[key][key2] = osstatus[key][key2]

    def _builddict(self, db, table, fields, key):
        resp = {}
        cur = db.cursor()
        try:
            cur.execute("select * from %s" % table)
        except sqlite3.OperationalError:
            return resp

        for row in cur:
            data = {}
            for field in fields:
                data[field] = row[field] if field in row.keys() else ''
            resp[row[key]] = data
        return resp

    def _buildglobal(self, db, table):
        resp = {}
        cur = db.cursor()
        cur.execute("select * from %s" % table)
        row = cur.fetchone()
        for field in row.keys():
            resp[field] = row[field]
        return resp

    def _builddict_join(self, db, join_table, join_index, join_field, table, field):
        #select platform_systemlocation_dns_servers.systemlocation_id as systemlocation_id, platform_dnsserver.address as address from platform_systemlocation_dns_servers left join platform_dnsserver on platform_systemlocation_dns_servers.dnsserver_id == platform_dnsserver.id

        # join_index is key
        # returns array of field
        resp = {}
        cur = db.cursor()
        cur.execute("select %s.%s as %s, %s.%s as %s from %s left join %s on %s.%s == %s.id" %
                    (join_table, join_index, join_index, table, field, field, join_table, table, join_table, join_field, table))
        for row in cur:
            if row[join_index] in resp:
                resp[row[join_index]].append(row[field])
            else:
                resp[row[join_index]] = [row[field]]
        return resp

    def _resolve_srv(self, target, service):
        if not do_dns:
            return None

        ret = []
        target = '.'.join([service, target])
        if target in self.cache:
            return self.cache[target]

        try:
            ans = dns.resolver.resolve(target, 'SRV')
        except Exception:
            return []

        for rec in ans:
            ret.append(str(rec.target)[:-1])
        self.cache[target] = ret
        return ret

    def _do_mssipdomain(self, mssip_domain):
        print("MSSIP Domain: %s" % (mssip_domain,))
        if do_dns:
            res = self._resolve_srv(mssip_domain, '_sipfederationtls._tcp')
            if res:
                print("              => " + ', '.join(res))
            else:
                print("              *** SRV DOES NOT RESOLVE ***")

    def _read_osstatus(self, filename):
        ret = {}
        try:
            fh = open(filename)
        except IOError:
            return ret

        for line in fh:
            if "cpuinfo" in line:
                fields = line.split(None, 3)
                hostname = fields[1].split('.')[0]
                if not hostname in ret:
                    ret[hostname] = {}
                count = 0
                flags = ''
                model = "Unknown"
                for line2 in fields[3].split('^M'):
                    if ': ' not in line2:
                        continue
                    (key, val) = line2.split(': ', 1)
                    if "processor" in key:
                        count += 1
                    elif "model name" in key:
                        if val.startswith('Intel(R) Xeon(R) CPU '):
                            val = val[21:]
                        model = val
                    elif "flags" in key:
                        if 'avx512' in val and 'xsave' in val:
                            flags = "AVX512"
                        elif 'avx2' in val and 'xsave' in val:
                            flags = "AVX2"
                        elif 'avx' in val and 'xsave' in val:
                            flags = "AVX"
                        elif 'sse4_2' in val:
                            flags = "SSE4.2"
                        elif 'popcnt' in val:
                            flags = "SSE4.1+"
                        else:
                            flags = "*** UNSUPPORTED ***"
                ret[hostname]["cpuinfo"] = { "cores": count, "model": model, "flags": flags }
            elif "meminfo" in line:
                fields = line.split(None, 3)
                hostname = fields[1].split('.')[0]
                memtotal = -1
                memfree = -1
                if not hostname in ret:
                    ret[hostname] = {}
                for line2 in fields[3].split('^M'):
                    fields2 = line2.split(None)
                    if not fields2:
                        continue
                    if fields2[0] == 'MemTotal:':
                        memtotal = int(fields2[1]) / (1000 ** 2)  # Yes I know that's not 1024^2
                    elif fields2[0] == 'MemFree:':
                        memfree = int(fields2[1]) / (1000 ** 2)
                ret[hostname]["meminfo"] = { "memtotal": memtotal, "memfree": memfree}
        return ret
                

    def confnodes(self):
        platformstatus_workervm = self._builddict(self.platform_status, 'platformstatus_workervm', ('last_reported', 'version', 'max_audio_calls', 'max_sd_calls', 'max_hd_calls', 'max_full_hd_calls', 'total_ram', 'cpu_count', 'cpu_model', 'cpu_capabilities', 'hypervisor', 'boot_time', 'tenet_last_contacted', 'sync_status'), 'configuration_id')
        if int(self.version['version-id'].split('.', 1)[0]) < 17:
            platformstatus_workervmlinks = self._builddict(self.platform_status, 'platformstatus_workervmlinks', ('from_address', 'to_address', 'status', 'last_active'), 'id')
        else:
            platformstatus_workervmlinks = {}
        platformstatus_alarm = self._builddict(self.platform_status, 'platformstatus_alarm', ('name', 'time_raised', 'node', 'instance', 'details'), 'id')
        platform_managementvm = self._buildglobal(self.configuration, 'platform_managementvm')
        platform_workervm = self._builddict(self.configuration, 'platform_workervm', ('name', 'hostname', 'address', 'alternative_fqdn', 'system_location_id', 'static_nat_address', 'secondary_address', 'maintenance_mode', 'cloud_bursting', 'transcoding', 'node_type'), 'id')
        platform_workervm_by_ip = self._builddict(self.configuration, 'platform_workervm', ('id', 'name', 'hostname', 'alternative_fqdn', 'system_location_id', 'static_nat_address', 'secondary_address', 'maintenance_mode', 'cloud_bursting', 'transcoding', 'node_type'), 'address')
        platform_location = self._builddict(
            self.configuration,
            'platform_systemlocation',
            ('name', 'h323_gatekeeper_id', 'sip_proxy_id', 'mssip_proxy_id', 'turn_server_id', 'stun_server_id',
                'policy_server_id', 'local_mssip_domain', 'overflow_location1_id', 'overflow_location2_id',
                'transcoding_location_id', 'media_qos', 'signalling_qos', 'http_proxy_id', 'mtu'), 'id')
        platform_h323 = self._builddict(self.configuration, 'platform_h323gatekeeper', ('name', 'address', 'port'), 'id')
        platform_sip = self._builddict(self.configuration, 'platform_sipproxy', ('name', 'address', 'port'), 'id')
        platform_mssip = self._builddict(self.configuration, 'platform_mssipproxy', ('name', 'address', 'port'), 'id')
        platform_teams = self._builddict(self.configuration, 'platform_teamsproxy', ('name', 'address', 'port'), 'id')
        platform_turnserver = self._builddict(self.configuration, 'platform_turnserver', ('name', 'address'), 'id')
        platform_stunserver = self._builddict(self.configuration, 'platform_stunserver', ('name', 'address'), 'id')
        platform_policyserver = self._builddict(self.configuration, 'platform_policyserver', ('name', 'url'), 'id')
        platform_httpproxy = self._builddict(self.configuration, 'platform_httpproxy', ('address', 'port'), 'id')
        platform_syslog = self._builddict(self.configuration, 'platform_syslogserver', ('address', 'port', 'transport'), 'id')
        platform_global = self._buildglobal(self.configuration, 'platform_global')
        platform_tuneables = self._builddict(self.configuration, 'platform_systemtuneable', ('setting',), 'name')
        platform_loglevels = self._builddict(self.configuration, 'platform_loglevel', ('name', 'level'), 'id')

        default_disabled_codecs = {'MP4A-LATM_128', 'H264_H_0', 'H264_H_1'}
        if int(self.version['version-id'].split('.', 1)[0]) == 21:
            default_disabled_codecs.add(u'VP9')
        try:
            platform_disabled_codecs = set(self._builddict_join(self.configuration, 'platform_global_disabled_codecs', 'global_id', 'disabledcodec_id', 'platform_disabledcodec', 'value').get(1, {}))
        except Exception:
            platform_disabled_codecs = None

        platform_dnsservers = self._builddict_join(self.configuration, 'platform_systemlocation_dns_servers', 'systemlocation_id', 'dnsserver_id', 'platform_dnsserver', 'address')
        platform_ntpservers = self._builddict_join(self.configuration, 'platform_systemlocation_ntp_servers', 'systemlocation_id', 'ntpserver_id', 'platform_ntpserver', 'address')
        platform_client_stunservers = self._builddict_join(self.configuration, 'platform_systemlocation_client_stun_servers', 'systemlocation_id', 'stunserver_id', 'platform_stunserver', 'address')
        if int(self.version['version-id'].split('.', 1)[0]) >= 33:
            platform_syslogservers = self._builddict_join(self.configuration, 'platform_systemlocation_syslog_servers', 'systemlocation_id', 'syslogserver_id', 'platform_syslogserver', 'address')
        else:
            platform_syslogservers = {}
        if int(self.version['version-id'].split('.', 1)[0]) >= 29:
            platform_client_turnservers = self._builddict_join(self.configuration, 'platform_systemlocation_client_turn_servers', 'systemlocation_id', 'turnserver_id', 'platform_turnserver', 'address')
        else:
            platform_client_turnservers = {}
        if int(self.version['version-id'].split('.', 1)[0]) >= 23:
            platform_eventsink = self._builddict_join(self.configuration, 'platform_systemlocation_event_sinks', 'systemlocation_id', 'eventsink_id', 'platform_eventsink', 'url')
        else:
            platform_eventsink = {}

        platform_managementvm_dnsservers = self._builddict_join(self.configuration, 'platform_managementvm_dns_servers', 'managementvm_id', 'dnsserver_id', 'platform_dnsserver', 'address')
        platform_managementvm_ntpservers = self._builddict_join(self.configuration, 'platform_managementvm_ntp_servers', 'managementvm_id', 'ntpserver_id', 'platform_ntpserver', 'address')

        print("Platform Version: %s (%s)" % (self.version['version-id'], self.version['pseudo-version']))
        print("Locations: %d" % (len(platform_location.keys()),))
        print("Conferencing Nodes: %d" % (len(platform_workervm.keys()),))
        print()
        print("Management Node: %s (%s)" % (platform_managementvm['hostname'], platform_managementvm['address']))
        if platform_managementvm['hostname'] in self.osstatus:
            osstatus = self.osstatus[platform_managementvm['hostname']]
            if 'cpuinfo' in osstatus and 'meminfo' in osstatus:
                print("CPU: %s (%s, %d cores), %d GB RAM" % (osstatus['cpuinfo']['model'], osstatus['cpuinfo']['flags'], osstatus['cpuinfo']['cores'], osstatus['meminfo']['memtotal']))
        if platform_managementvm['id'] in platform_managementvm_dnsservers:
            print("DNS: %s" % ', '.join(platform_managementvm_dnsservers[platform_managementvm['id']]))
        else:
            print("DNS: *** NONE ***")

        if platform_managementvm['id'] in platform_managementvm_ntpservers:
            print("NTP: %s" % ', '.join(platform_managementvm_ntpservers[platform_managementvm['id']]))
        else:
            print("NTP: *** NONE ***")

        if platform_managementvm.get('http_proxy_id'):
            print("HTTP Proxy: %s:%s" % (platform_httpproxy[platform_managementvm['http_proxy_id']]['address'], platform_httpproxy[platform_managementvm['http_proxy_id']]['port']))

        if platform_managementvm.get('mtu'):
            print("MTU: %s" % (platform_managementvm['mtu'],))

        addresses = [platform_managementvm['address']]

        print()
        syslogs = []
        for syslog in platform_syslog.values():
            syslogs.append("%s:%s/%s" % (syslog['address'], syslog['port'], syslog['transport'].upper()))
        if len(syslogs) > 0:
            print("Syslog servers: " + ', '.join(syslogs))
        print("Signalling ports: %d-%d" % (platform_global['signalling_ports_start'], platform_global['signalling_ports_end']))
        print("Media ports: %d-%d" % (platform_global['media_ports_start'], platform_global['media_ports_end']))
        if platform_global['local_mssip_domain']:
            self._do_mssipdomain(platform_global['local_mssip_domain'])
        if int(self.version['version-id'].split('.', 1)[0]) < 23:
            print("1080p:", "Enabled" if platform_global.get('allow_1080p') else "Disabled")
        else:
            if platform_global.get('max_callrate_in') or platform_global.get('max_callrate_out'):
                print("Global Max Resolution: %s (In: %s, Out: %s)" % (platform_global.get('max_pixels_per_second').upper(), platform_global.get('max_callrate_in', 'None'), platform_global.get('max_callrate_out', 'None')))
            else:
                print("Global Max Resolution:", platform_global.get('max_pixels_per_second').upper())
        if 'enable_lync_vbss' in platform_global:
            print("VBSS:", "Enabled" if platform_global.get('enable_lync_vbss') else "Disabled")
        if 'enable_turn_443' in platform_global:
            print("TURN443:", "Enabled" if platform_global.get('enable_turn_443') else "Disabled")
        disabled_features = []
        for key in ['enable_sip', 'enable_sip_udp', 'enable_h323', 'enable_application_api', 'enable_webrtc', 'enable_rtmp', 'enable_chat', 'enable_fecc', 'enable_dialout']:
            if not platform_global.get(key, -1):
                disabled_features.append(key[7:].upper())
        if disabled_features:
            print("Disabled protocols:", ', '.join(disabled_features))
        if platform_disabled_codecs is not None:
            added_codecs = default_disabled_codecs - platform_disabled_codecs
            missing_codecs = platform_disabled_codecs - default_disabled_codecs
            if added_codecs:
                print("Enabled codecs:", ', '.join(added_codecs))
            if missing_codecs:
                print("Disabled codecs:", ', '.join(missing_codecs))

        debuglogs = []
        for log in platform_loglevels.values():
                if log['level'] == 'DEBUG':
                    debuglogs.append("%s" % (log['name']))
        if len(debuglogs) > 0:
            print()
            print("Logs set to debug: " + ', '.join(debuglogs))

        if 'default_webapp_alias_id' in platform_global and platform_global['default_webapp_alias_id']:
            platform_webappalias = self._builddict(self.configuration, 'platform_webappalias', ('slug', 'webapp_type'), 'id')
            defaultalias = platform_webappalias[platform_global['default_webapp_alias_id']]
            print("Default webapp: /%s (%s)" % (defaultalias['slug'], defaultalias['webapp_type'].capitalize()))
        elif 'default_to_new_webapp' in platform_global:
            print("Default webapp: " + ("Webapp2" if platform_global['default_to_new_webapp'] else "Webapp1"))

        blob = {'locations':{}}

        location_errors = {}
        for location_id in sorted(platform_location.keys(), key=lambda k: platform_location[k]['name']):
            loc = platform_location[location_id]
            print()
            print(loc['name'])
            print(len(loc['name']) * "=")
            blob[loc['name']] = {'nodes': {}}
            if location_id in platform_dnsservers:
                print("DNS: %s" % ', '.join(platform_dnsservers[location_id]))
                blob[loc['name']]['dns_servers'] = platform_dnsservers[location_id]
            else:
                print("DNS: *** NONE ***")

            if location_id in platform_ntpservers:
                print("NTP: %s" % ', '.join(platform_ntpservers[location_id]))
                blob[loc['name']]['ntp_servers'] = platform_ntpservers[location_id]
            else:
                print("NTP: *** NONE ***")

            if loc['mtu']:
                print("MTU: %s" % (loc['mtu'],))

            if location_id in platform_syslogservers:
                print("Syslog Servers: %s" % ', '.join(platform_syslogservers[location_id]))
                blob[loc['name']]['syslog_servers'] = platform_syslogservers[location_id]

            if loc['local_mssip_domain']:
                self._do_mssipdomain(loc['local_mssip_domain'])

            if loc['media_qos'] or loc['signalling_qos']:
                print("QoS: %d (Media), %d (Signalling)" % (loc['media_qos'], loc['signalling_qos']))

            if loc['transcoding_location_id']:
                print("Transcoding Location: %s" % (platform_location[loc['transcoding_location_id']]['name'],))

            if loc['overflow_location1_id']:
                overflow = "Overflow: %s" % (platform_location[loc['overflow_location1_id']]['name'],)
                if loc['overflow_location2_id']:
                    overflow += ", %s" % (platform_location[loc['overflow_location2_id']]['name'],)
                print(overflow)

            print()

            if loc['sip_proxy_id']:
                sip = platform_sip[loc['sip_proxy_id']]
                print("SIP Proxy          : %s (%s)" % (sip['address'], sip['name']))
                blob[loc['name']]['sip_proxy'] = sip

            if loc['h323_gatekeeper_id']:
                h323 = platform_h323[loc['h323_gatekeeper_id']]
                print("H323 Gatekeeper    : %s (%s)" % (h323['address'], h323['name']))
                blob[loc['name']]['h323_gatekeeper'] = h323

            if loc['mssip_proxy_id']:
                mssip = platform_mssip[loc['mssip_proxy_id']]
                print("MSSIP Proxy        : %s (%s)" % (mssip['address'], mssip['name']))
                blob[loc['name']]['mssip_proxy'] = mssip

            if loc['policy_server_id']:
                data = platform_policyserver[loc['policy_server_id']]
                print("Policy Profile     : %s (%s)" % (data['name'], data['url'] or "local policy"))
                blob[loc['name']]['policy_server'] = data

            if loc['http_proxy_id']:
                httpproxy = platform_httpproxy[loc['http_proxy_id']]
                print("HTTP Proxy         : %s:%s" % (httpproxy['address'], httpproxy['port']))
                blob[loc['name']]['http_proxy'] = httpproxy

            if location_id in platform_eventsink:
                print("Event Sinks        : %s" % ', '.join(platform_eventsink[location_id]))
                blob[loc['name']]['event_sinks'] = platform_eventsink[location_id]

            if loc['turn_server_id']:
                turn = platform_turnserver[loc['turn_server_id']]
                print("TURN Server        : %s (%s)" % (turn['address'], turn['name']))
                blob[loc['name']]['turn_server'] = turn

            if loc['stun_server_id']:
                stun = platform_stunserver[loc['stun_server_id']]
                print("STUN Server        : %s (%s)" % (stun['address'], stun['name']))
                blob[loc['name']]['stun_server'] = stun

            if location_id in platform_client_stunservers:
                if len(platform_client_stunservers[location_id]) > 0:
                    print("Client STUN Servers: %s" % ', '.join(platform_client_stunservers[location_id]))
                    blob[loc['name']]['client_stun_server'] = platform_client_stunservers[location_id]
            elif loc['turn_server_id'] and location_id not in platform_client_turnservers:
                print("Client STUN Servers: *** NONE ***")

            if location_id in platform_client_turnservers:
                if len(platform_client_turnservers[location_id]) > 0:
                    print("Client TURN Servers: %s" % ', '.join(platform_client_turnservers[location_id]))
                    blob[loc['name']]['client_turn_server'] = platform_client_turnservers[location_id]

            header = ['Name', 'IP Address', 'SIP TLS FQDN', 'Static NAT', 'Last Contacted', 'Version', 'Type']
            if platform_global.get('allow_1080p'):
                header.append('FHD')
            header.extend(['HD', 'SD', 'Audio', 'CPU', 'Cores', 'RAM', 'Hypervisor', 'Boot Time', ''])
            workers = [header]
            worker_data = []
            for worker_id in sorted(platform_workervm.keys(), key=lambda k: platform_workervm[k]['name']):
                worker = platform_workervm[worker_id]
                if worker['system_location_id'] != location_id:
                    continue
                status = platformstatus_workervm[worker_id]
                node_type = 'C'
                if worker['node_type']:
                    node_type = worker['node_type'][:1]
                elif worker['transcoding'] == 0:
                    node_type = 'P'
                last_reported = "Unknown"
                if status['last_reported']:
                    last_reported = status['last_reported']
                elif status['tenet_last_contacted']:
                    last_reported = status['tenet_last_contacted'][:19]
                data = [worker['hostname'], worker['address'], worker['alternative_fqdn'], 
                        worker['static_nat_address'] if worker['static_nat_address'] and not worker['secondary_address'] else '', 
                        last_reported, status['version'], node_type]
                if platform_global.get('allow_1080p'):
                    data.append(status['max_full_hd_calls'])
                data.extend([status['max_hd_calls'], status['max_sd_calls'], status['max_audio_calls']])
                if status['cpu_model']:
                    if status['cpu_model'].startswith('Intel(R) Xeon(R) CPU '):
                        status['cpu_model'] = status['cpu_model'][21:]
                    elif status['cpu_model'].startswith('Intel(R) Xeon(R) '):
                        status['cpu_model'] = status['cpu_model'][17:]
                    data.extend(["%s (%s)" % (status['cpu_model'], status['cpu_capabilities']), status['cpu_count'], str(status['total_ram'] // (1000**2)) + " GB"])
                elif worker['hostname'] in self.osstatus and 'cpuinfo' in self.osstatus[worker['hostname']]:
                    data.extend(["%s (%s)" % (self.osstatus[worker['hostname']]['cpuinfo']['model'], self.osstatus[worker['hostname']]['cpuinfo']['flags']),
                        self.osstatus[worker['hostname']]['cpuinfo']['cores'], str(self.osstatus[worker['hostname']]['meminfo']['memtotal']) + " GB"])
                else:
                    data.extend(['', '', ''])
                data.append(status['hypervisor'])
                if status['boot_time']:
                    data.append(status['boot_time'][:19])
                else:
                    data.append('')
                additional = ''
                if worker['cloud_bursting']:
                    if status['sync_status'] == 'SUSPENDED':
                        additional += '* CLOUD BURSTING (DOWN) *'
                    else:
                        additional += '* CLOUD BURSTING (UP) *'
                if worker['maintenance_mode']:
                    additional += '* MAINTENANCE MODE *'
                data.append(additional)
                addresses.append(worker['address'])
                workers.append(data)
                if worker['secondary_address']:
                    workers.append(['', worker['secondary_address'], '', worker['static_nat_address'] if worker['static_nat_address'] else '', '', '', '', '', '', ''])
                worker_data.append({'node_type': node_type, 'static_nat': worker['static_nat_address'], 'sip_tls_fqdn': worker['alternative_fqdn'], 'address': worker['address'], 'secondary_address': worker['secondary_address']})

            location_errors[loc['name']] = []
            if len({x['node_type'] for x in worker_data}) > 1:
                location_errors[loc['name']].append("Mix of Proxy and Transcoding Nodes")
            if len({bool(x['static_nat']) for x in worker_data}) > 1:
                location_errors[loc['name']].append("Only some nodes have Static NAT")
            if len({bool(x['sip_tls_fqdn']) for x in worker_data}) > 1:
                location_errors[loc['name']].append("Only some nodes have SIP TLS FQDN")

            if do_dns:
                for worker in worker_data:
                    addrs = {worker['address'], worker['secondary_address'], worker['static_nat']}
                    ans = []
                    if worker['sip_tls_fqdn']:
                        try:
                            ans = dns.resolver.resolve(worker['sip_tls_fqdn'])
                        except Exception:
                            pass
                    else:
                        continue

                    targets = {x.address for x in ans}
                    if not targets:
                        location_errors[loc['name']].append("%s does not resolve" % (worker['sip_tls_fqdn'],))
                    elif not targets & addrs:
                        location_errors[loc['name']].append("%s does not resolve to a configured IP address" % (worker['sip_tls_fqdn'],))

            print()
            print("Conferencing Nodes : %d" % len(worker_data))
            print()
            tabulate(workers)
            print()

        print()
        print("Node Issues")
        print("===========")
        print("Version Mismatches:")
        ver = re.compile(r"([\d.]+) \(([\d.]+)\)")
        count = 0
        for worker_id in platformstatus_workervm:
            worker = platformstatus_workervm[worker_id]
            try:
                pseudo = ver.match(worker['version']).group(2)
            except IndexError:
                pseudo = "None"
            if pseudo != self.version['pseudo-version'] and worker_id in platform_workervm:
                print("  %s (%s): %s" % (platform_workervm[worker_id]['address'], platform_workervm[worker_id]['hostname'], worker['version']))
                count += 1
        if count == 0:
            print("  None")
        print()

        print("Last Contacted over 5 minutes ago:")
        count = 0
        data = []
        powered_off = []

        if int(self.version['version-id'].split('.', 1)[0]) < 29:
            for worker_id in platformstatus_workervm:
                if worker_id not in platform_workervm:
                    continue
                worker = platformstatus_workervm[worker_id]
                data.append({'name': platform_workervm[worker_id]['hostname'],
                             'address': platform_workervm[worker_id]['address'],
                             'last_reported_str': worker['last_reported'],
                             'last_reported': datetime.strptime(worker['last_reported'][:19], '%Y-%m-%d %H:%M:%S') if worker['last_reported'] else datetime.min})
        else:
            for worker_id in platformstatus_workervm:
                if worker_id not in platform_workervm:
                    continue
                worker = platformstatus_workervm[worker_id]
                data.append({'name': platform_workervm[worker_id]['hostname'],
                             'address': platform_workervm[worker_id]['address'],
                             'last_reported_str': worker['tenet_last_contacted'][:19] if worker['tenet_last_contacted'] else 'Unknown',
                             'last_reported': datetime.strptime(worker['tenet_last_contacted'][:19], '%Y-%m-%d %H:%M:%S') if worker['tenet_last_contacted'] else datetime.min})

        data = sorted(data, key=operator.itemgetter('last_reported'))
        if data:
            most_recent = data[-1]['last_reported']
            delta = timedelta(seconds=600)
            for item in data:
                if most_recent - item['last_reported'] > delta:
                    print("  %s (%s): %s" % (item['address'], item['name'], item['last_reported_str']))
                    powered_off.append(item['address'])  # For v17+, discount any of these from connectivity errors
                    count += 1
        if count == 0:
            print("  None")
        print()

        print("Resource issues:")
        count = 0
        for worker_id in platformstatus_workervm:
            if worker_id not in platform_workervm:
                continue

            worker = platform_workervm[worker_id]
            status = platformstatus_workervm[worker_id]
            cpu_count = 0
            total_ram = 0

            if status.get('total_ram'):
                total_ram = status['total_ram'] // (1000**2)
            elif  worker['hostname'] in self.osstatus and 'meminfo' in self.osstatus[worker['hostname']]:
                total_ram = self.osstatus[worker['hostname']]['meminfo']['memtotal']

            if status.get('cpu_count'):
                cpu_count = status['cpu_count']
            elif  worker['hostname'] in self.osstatus and 'cpuinfo' in self.osstatus[worker['hostname']]:
                cpu_count = self.osstatus[worker['hostname']]['cpuinfo']['cores']

            if cpu_count > 14:
                # NUMA pinned?
                max_hd_target = int(cpu_count * 1.3)
            else:
                max_hd_target = int(cpu_count * 1.8)

            if total_ram < cpu_count or status['max_hd_calls'] < max_hd_target:
                count += 1
                print("  %s (%s cores, %s GB RAM, %s HD calls)" % (worker['hostname'], cpu_count, total_ram, status['max_hd_calls']))
        if count == 0:
            print("  None")
        print()

        failed_links = {}
        if platformstatus_workervmlinks:
            links = sorted(sorted(platformstatus_workervmlinks.values(), key=operator.itemgetter('from_address')), key=operator.itemgetter('to_address'))
            powered_off = copy.copy(addresses)
            for link in links:
                if link['from_address'] in addresses and link['to_address'] in addresses:
                    if link['status'] == 'ACTIVE':
                        if link['from_address'] in powered_off:
                            powered_off.remove(link['from_address'])
                        #if link['to_address'] in powered_off:
                        #    powered_off.remove(link['to_address'])
                    else:
                        ind = "%s-%s" % (link['from_address'], link['to_address'])
                        failed_links[ind] = link
        else:
            for alarm in platformstatus_alarm.values():
                if alarm['name'] != 'connectivity_lost':
                    continue

                if "=" in alarm['instance']:
                    details = {}
                    for pair in alarm['instance'].split(', '):
                        (key, val) = pair.split('=', 1)
                        details[key] = val

                    ind = "%s-%s" % (details['Source'], details['Destination'])
                    failed_links[ind] = {'from_address': details['Source'],
                                         'to_address': details['Destination'],
                                         'status': 'EXPIRED',
                                         'last_active': alarm['time_raised'][:19]}
                else:
                    for source in alarm['details'].split(', '):
                        ind = "%s-%s" % (source, alarm['node'])
                        failed_links[ind] = {'from_address': source,
                                             'to_address': alarm['node'],
                                             'status': 'EXPIRED',
                                             'last_active': alarm['time_raised'][:19]}

        for link_key, link in failed_links.copy().items():
            if link['from_address'] in powered_off or link['to_address'] in powered_off:
                del failed_links[link_key]
                continue

            ind = "%s-%s" % (link['from_address'], link['to_address'])
            ind2 = "%s-%s" % (link['to_address'], link['from_address'])
            if ind not in failed_links:
                continue
            if ind2 in failed_links:
                del failed_links[ind2]
                link['dir'] = '<->'
            else:
                link['dir'] = ' ->'

        def _get_location_by_ip(address):
            if platform_managementvm['address'] == address:
                return "Management Node"
            elif address in platform_workervm_by_ip:
                return platform_location[platform_workervm_by_ip[address]['system_location_id']]['name']
            return "Unknown"

        print("Nodes with no connectivity:")
        for address in powered_off:
            print("  %s [%s]" % (address, _get_location_by_ip(address)))

        if len(powered_off) == 0:
            print("  None")
        print()

        print("Additional inter-node connectivity issues:")
        count = 0
        for link in sorted(failed_links.values(), key=operator.itemgetter('last_active')):
            print("%15s %s %15s: %s (%s) [%s %s %s]" % (link['from_address'], link['dir'], link['to_address'], link['status'], link['last_active'], _get_location_by_ip(link['from_address']), link['dir'], _get_location_by_ip(link['to_address'])))
            count += 1
            
        if count == 0:
            print("  None")


        print()
        print("Other Issues")
        print("============")
        print("SIP TLS FQDN Clashes:")
        count = 0
        data = {}
        for worker in platform_workervm.values():
            if not worker['alternative_fqdn']:
                continue
            if worker['alternative_fqdn'] not in data:
                data[worker['alternative_fqdn']] = []
            data[worker['alternative_fqdn']].append("%s (%s)" % (worker['hostname'], worker['address']))
        for key in sorted(data.keys()):
            if len(data[key]) > 1:
                print("  %s: %s" % (key, ', '.join(data[key])))
                count += 1
        if count == 0:
            print("  None")
        print()

        print("Potentially erroneous node configurations:")
        count = 0
        for (key, value) in location_errors.items():
            if not value:
                continue
            for item in value:
                print("  %s: %s" % (key, item))
                count += 1
        if count == 0:
            print("  None")
        print()


        print("Alarms (excluding connectivity)")
        print("===============================")
        alarms = {}
        for alarm in platformstatus_alarm.values():
            if alarm['name'] in ['configuration_sync_failure', 'connectivity_lost']:
                continue
            if alarm['name'] in alarms:
                alarms[alarm['name']].append(alarm)
            else:
                alarms[alarm['name']] = [alarm]

        for (alarmname, alarmlist) in alarms.items():
            print(alarmname)
            for alarm in sorted(alarmlist, key=operator.itemgetter('time_raised')):
                ret = "  source: %s, raised: %s" % (alarm['node'], alarm['time_raised'][:19])
                if alarm['instance']:
                    ret += ', instance: ' + alarm['instance'].strip()
                if alarm['details']:
                    ret += ', details: ' + alarm['details'].strip()
                print(ret)
            print()

        if len(alarms) == 0:
            print("None")
            print()

        gatewayrules = self._builddict(self.configuration, 'conferencing_gatewayroutingrule', ('name', 'match_string', 'replace_string', 'match_incoming_sip', 'match_incoming_h323', 'match_incoming_webrtc', 'match_incoming_mssip', 'match_incoming_calls', 'match_outgoing_calls', 'match_incoming_only_if_registered', 'match_string_full', 'outgoing_protocol', 'enable', 'called_device_type', 'match_source_location_id', 'outgoing_location_id', 'mssip_proxy_id', 'sip_proxy_id', 'h323_gatekeeper_id', 'teams_proxy_id'), 'priority')
        print("Gateway Rules")
        print("=============")
        if len(gatewayrules.keys()) == 0:
            print("None")
        for prio in sorted(gatewayrules.keys()):
            rule = gatewayrules[prio]
            print("%3d %s %s" % (prio, rule['name'], '' if rule['enable'] else ' ** DISABLED **'))
            protos = []
            if rule['match_incoming_calls']:
                if rule['match_incoming_sip']:
                    protos.append("SIP")
                if rule['match_incoming_h323']:
                    protos.append("H323")
                if rule['match_incoming_webrtc']:
                    protos.append("WebRTC")
                if rule['match_incoming_mssip']:
                    protos.append("MSSIP")
                if rule['match_incoming_only_if_registered']:
                    protos.append("Registered only")
            if rule['match_outgoing_calls']:
                protos.append("Outgoing")
            ret = "%s (%s) " % (rule['match_string'], ', '.join(protos))
            if rule['match_source_location_id']:
                ret += "[%s] " % (platform_location[rule['match_source_location_id']]['name'],)
            outgoing_protocol = rule['outgoing_protocol'].upper()
            if rule['outgoing_protocol'] == 'mssip' and rule['mssip_proxy_id']:
                outgoing_protocol += " / " + platform_mssip[rule['mssip_proxy_id']]['address']
            if rule['outgoing_protocol'] == 'sip' and rule['sip_proxy_id']:
                outgoing_protocol += " / " + platform_sip[rule['sip_proxy_id']]['address']
            if rule['outgoing_protocol'] == 'h323' and rule['h323_gatekeeper_id']:
                outgoing_protocol += " / " + platform_h323[rule['h323_gatekeeper_id']]['address']
            if rule['outgoing_protocol'] == 'teams' and rule['teams_proxy_id']:
                outgoing_protocol += " / " + platform_teams[rule['teams_proxy_id']]['address']
            ret += "-> %s (%s / %s)" % (rule['replace_string'], rule['called_device_type'], outgoing_protocol)
            if rule['outgoing_location_id']:
                ret += " [%s]" % (platform_location[rule['outgoing_location_id']]['name'],)
            print(ret)
            if rule['outgoing_protocol'] == 'teams' and rule['teams_proxy_id'] and do_dns:
                try:
                    dns.resolver.resolve(platform_teams[rule['teams_proxy_id']]['address'])
                except Exception:
                    print("> *** DOES NOT RESOLVE ***")
            if rule['match_string_full']:
                print("> FULL MATCH (For Lync IVR)")
                if (not rule['match_string'].startswith(".+") or not rule['match_string'].endswith(".*")) and \
                    rule['called_device_type'].startswith('mssip'):
                    print("> *** INSUFFICIENT WILDCARDS? ***")
            print()

        if platform_tuneables:
            print()
            print("System Tuneables")
            print("================")

            for (key, val) in platform_tuneables.items():
                print("{}: {}".format(key, val['setting']))

            print()

        security_changes = SecurityCheck(rootdir).read_security_json()
        if security_changes is not None:
            if security_changes:
                print()
                print("Security Wizard Changes")
                print(len("Security Wizard Changes") * "=")
                for key in sorted(security_changes.keys()):
                    print("%s: %s" % (key, security_changes[key]))

            print()

    def license_list(self):
        licenses = []
        print()
        print("Licenses")
        print("========")
        if 'fulfillment_records' not in self.licenses or len(self.licenses['fulfillment_records']) == 0:
            print("*** NONE ***")
            return

        vmr_required = False
        for license in self.licenses['fulfillment_records']:
            if license['expiration_date'] == 'permanent':
                expires = datetime.max
            else:
                expires = datetime.strptime(license['expiration_date'], '%d-%b-%Y')

            if 'start_date' in license:
                start_date = datetime.strptime(license['start_date'], '%d-%b-%Y')
            else:
                start_date = datetime.min

            if license['concurrent_overdraft'] == 2147483646:
                count = license['concurrent_overdraft']
            else:
                count = license['concurrent']

            if 'features' in license:
                for feature in license['features'].strip().split('INCREMENT '):
                    if not feature:
                        continue

                    features = feature.split()
                    if '100.00000' in features:
                        vmr_required = True

                    licenses.append({'key': license['entitlement_id'],
                                     'type': features[0],
                                     'count': count,
                                     'starts': start_date,
                                     'expires': expires,
                                     'status': license.get('status', 'Unknown')})
            else:
                licenses.append({'key': license['entitlement_id'],
                                 'type': license['license_type'],
                                 'count': count,
                                 'starts': start_date,
                                 'expires': expires,
                                 'status': license.get('status', 'Unknown')})

        total_audio = 0
        total_ports = 0
        total_scheduling = 0
        total_vmrs = 0
        totals = {}
        for license in sorted(licenses, key=operator.itemgetter('expires')):
            print("%s: %s %s; %s" % (
                license['key'],
                "Infinite" if license['count'] == 2147483646 else license['count'],
                license['type'], license['status']), end=" ")
            if license['expires'] < datetime.now():
                print("(EXPIRED %s)" % (license['expires'].strftime('%Y-%m-%d'),))
            elif license['expires'] == datetime.max:
                print("(PERMANENT)")
                if license['type'] in totals:
                    totals[license['type']] += license['count']
                else:
                    totals[license['type']] = license['count']
            elif license['starts'] > datetime.now():
                print("(STARTS %s until %s)" % (license['starts'].strftime('%Y-%m-%d'), license['expires'].strftime('%Y-%m-%d')))
            else:
                print("(until %s)" % (license['expires'].strftime('%Y-%m-%d'),))
                if license['type'] in totals:
                    totals[license['type']] += license['count']
                else:
                    totals[license['type']] = license['count']

        print()
        for lic_type in sorted(totals.keys()):
            lic_total = totals[lic_type]
            if lic_total == 2147483646:
                lic_total = "Infinite"
            print("Total active %-9s : %s" % (lic_type, lic_total))
        print("VMR licenses required  : %s" % (vmr_required,))

        cur = self.configuration.cursor()
        cur.execute("select count(*) from conferencing_conference;")
        row = cur.fetchone()
        vmr_count = row[row.keys()[0]]
        print("Total VMRs configured  : %d" % (vmr_count,))

    def tls_certs(self):
        platform_workervm = self._builddict(self.configuration, 'platform_workervm', ('name', 'hostname', 'domain', 'address', 'alternative_fqdn', 'tls_certificate_id'), 'id')
        platform_tlscertificate = self._builddict(self.configuration, 'platform_tlscertificate', ('certificate',), 'id')
        platform_trustedca = self._builddict(self.configuration, 'platform_trustedca', ('certificate',), 'id')

        certs = {}
        intermediates = {}
        cacerts = []

        if platform_trustedca:
            for cert_id in platform_trustedca.keys():
                cacerts.append(platform_trustedca[cert_id]['certificate'])
        elif os.path.exists(os.path.join(self.certsdir, 'ca-certificates.pem')):
            with open(os.path.join(self.certsdir, 'ca-certificates.pem'), "rb") as cas:
                cert_data = None
                for line in cas:
                    if cert_data:
                        cert_data += line
                    if b"BEGIN CERTIFICATE" in line:
                        cert_data = line
                    if b"END CERTIFICATE" in line:
                        cacerts.append(cert_data)
                        cert_data = None

        for cacert in cacerts:
            try:
                cert = x509.load_pem_x509_certificate(cacert.encode())
            except ValueError:
                continue

            data = {'CN': cert.subject.rfc4514_string(),
                    'Issuer': cert.issuer.rfc4514_string(),
                    'Expiry': cert.not_valid_after_utc,}
            intermediates[cert.subject.rfc4514_string()] = data


        def validate_issuer(issuer):
            if issuer not in intermediates:
                return False

            intermediate = intermediates[issuer]
            if intermediate['Issuer'] == intermediate['CN'] or intermediate['Issuer'] is None:
                return True

            return validate_issuer(intermediate['Issuer'])

        tlscerts = { key: [] for key in platform_tlscertificate.keys() }
        for worker_id in sorted(platform_workervm.keys(), key=lambda k: platform_workervm[k]['name']):
            worker = platform_workervm[worker_id]
            fqdn = "%s.%s" % (worker['hostname'], worker['domain'])
            if worker['alternative_fqdn']:
                fqdn += ' [%s]' % worker['alternative_fqdn']
            if worker['tls_certificate_id'] in tlscerts:
                tlscerts[worker['tls_certificate_id']].append(fqdn)

        for cert_id in tlscerts.keys():
            if len(tlscerts[cert_id]) == 0:
                # We only care about certs which are assigned to nodes
                continue

            try:
                cert = x509.load_pem_x509_certificate(platform_tlscertificate[cert_id]['certificate'].encode())
            except ValueError:
                continue

            fqdn = ', '.join(tlscerts[cert_id])
            sn = cert.serial_number
            issuer = cert.issuer.rfc4514_string()
            data = {'CN': cert.subject.rfc4514_string(),
                    'Issuer': issuer,
                    'Chain': validate_issuer(issuer),
                    'Expiry': cert.not_valid_after_utc,
                    'Signature': cert.signature_algorithm_oid._name.encode(),
                    'Hosts': [fqdn] }

            san = []
            for ext in cert.extensions:
                if ext.oid == x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                    for entry in ext.value:
                        # valid instances are documented at:
                        # https://github.com/pyca/cryptography/blob/main/src/cryptography/x509/general_name.py
                        if isinstance(entry, DNSName):
                            san.append(f'DNS:{entry.value}')
                        if isinstance(entry, IPAddress):
                            san.append(f'IP:{entry.value}')
                    break

            if san:
                data['SANs'] = ', '.join(san)

            if sn in certs:
                certs[sn]['Hosts'].append(fqdn)
            else:
                certs[sn] = data

        print()
        print("TLS Certificates")
        print("================")
        for cert in sorted(certs.values(), key=operator.itemgetter('CN')):
            print(cert['CN'])
            if cert['Issuer']:
                print(" -> Issuer: %s (Validates: %s)" % (cert.get('Issuer', 'None'), cert['Chain']))
            else :
                print(" -> Issuer: None (Validates: %s)" % cert['Chain'])
            print("    Expiry: %s" % cert['Expiry'])
            print(" Signature: %s" % cert['Signature'].decode())
            if cert.get('SANs'):
                print("      SANs: %s" % cert['SANs'])
            print(" => %s" % '\n    '.join(cert['Hosts']))
            print()


def main(rootdir):
    """Main processing - rootdir is /opt/pexip/share equivalent under which databases lie"""
    dba = DBAnalyser(rootdir)
    dba.confnodes()
    if do_ssl:
        dba.tls_certs()
    dba.license_list()
    

if __name__ == "__main__":
    if len(sys.argv) > 1:
        rootdir = sys.argv[1]
    else:
        rootdir = os.getcwd()
    try:
        if os.path.isdir(rootdir):
            main(rootdir)
        else:
            print("Usage: dbsummary /path/to/root/fs")
    except (IOError, KeyboardInterrupt):
        pass
