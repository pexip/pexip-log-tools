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

# mjxsummary: parse snapshot database for mjx data
#
# v1.4 - Add Graph integration to support v28+
# v1.3 - Fix overuse of replace and key issue in service account
# v1.2 - update version.json path for v27+
# v1.1 - add ms oauth redirect validation check
# v1.0 - remove dbsummary dependency
# v0.9 - port to python3
# v0.8
#
# Disable "Invalid constant name"                       pylint: disable=C0103
# Disable "Line too long"                               pylint: disable=C0301
# Disable "Too many lines in module"                    pylint: disable=C0302
# Disable "Missing docstring"                           pylint: disable=C0111
# Disable "Too many branches"                           pylint: disable=R0912
# Disable "Too many statements"                         pylint: disable=R0915
# Disable "Unnecessary parens"                          pylint: disable=C0325
# Disable "Wrong Import Position"                       pylint: disable=C0413
# Disable "Access to a protected member"                pylint: disable=W0212

display_extended = 1 # print extended settings
display_endpoints = 1 # print endpoints
display_status_items = 1 # print status database results

import json
import os
import sqlite3
import sys

def replace(value): # v0.4 - fixup to make it easier to add items_to_replace
    items_to_replace = {
        ('0', 'No'),
        ('1', 'Yes'),
        ('GLOBAL', 'PROFILE SET'),
        ('_', ' ')
    }
    for oldvalue, newvalue in items_to_replace:
        value = value.replace(oldvalue, newvalue)
    return value

def get_worker(workers, current):
    for key in workers.keys():
        if current == key:
            node = '%s (%s)' % (workers[key]['name'], key)
            return node

def builddict(db, table, fields, key):
    resp = {}
    cur = db.cursor()
    cur.execute("select * from %s" % table)
    for row in cur:
        data = {}
        for field in fields:
            data[field] = row[field] if field in row.keys() else ''
        resp[row[key]] = data
    return resp

def builddict_join(db, join_table, join_index, join_field, table, field):
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

def main(rootdir):
    """Main processing"""
    try:
        if os.path.isdir(os.path.join(rootdir, 'opt/pexip/share/status/db')):
            statusdir = os.path.join(rootdir, 'opt/pexip/share/status/db')
        else:
            statusdir = os.path.join(rootdir, 'opt/pexip/share/status')
        platform_status = sqlite3.connect(os.path.join(statusdir, 'platform_status.db'))
        platform_status.row_factory = sqlite3.Row
        conferencing_status = sqlite3.connect(os.path.join(statusdir, 'conferencing_status.db'))
        conferencing_status.row_factory = sqlite3.Row
        configuration = sqlite3.connect(os.path.join(rootdir, 'opt/pexip/share/config/conferencing_configuration.db'))
        configuration.row_factory = sqlite3.Row
        if os.path.exists(os.path.join(rootdir, 'opt/pexip/lib/python2.7/site-packages/si/web/management/conf/static/version.json')):
            version = json.load(open(os.path.join(rootdir, 'opt/pexip/lib/python2.7/site-packages/si/web/management/conf/static/version.json'), 'r'))
        else:
            version = json.load(open(os.path.join(rootdir, 'opt/pexip/share/web/static/version/version.json'), 'r'))
    except:
        print("FATAL: Unable to open database files")
        print("Usage: %s <snapshot folder>" % (os.path.basename(__file__)))
        sys.exit(2)
    if version['version-id'] < '23':
        print("FATAL: Requires Pexip Infinity version 23 or higher")
        sys.exit(2)
    meetings = 0
    platformstatus_alarm = builddict(platform_status, 'platformstatus_alarm', ('name', 'time_raised', 'node', 'instance', 'details'), 'id')
    if version['version-id'] >= '28':
        platform_mjxintegration = builddict(configuration, 'platform_mjxintegration', ('name', 'description', 'end_buffer', 'ep_username', 'ep_password', 'ep_verify_certificate', 'ep_use_https', 'exchange_deployment_id', 'google_deployment_id', 'display_upcoming_meetings', 'enable_non_video_meetings', 'replace_empty_subject', 'replace_subject_type', 'enable_private_meetings', 'process_alias_private_meetings', 'start_buffer', 'replace_subject_template', 'use_webex', 'webex_client_id', 'webex_redirect_uri', 'graph_deployment_id'), 'id')
    elif version['version-id'] >= '25':
        platform_mjxintegration = builddict(configuration, 'platform_mjxintegration', ('name', 'description', 'end_buffer', 'ep_username', 'ep_password', 'ep_verify_certificate', 'ep_use_https', 'exchange_deployment_id', 'google_deployment_id', 'display_upcoming_meetings', 'enable_non_video_meetings', 'replace_empty_subject', 'replace_subject_type', 'enable_private_meetings', 'process_alias_private_meetings', 'start_buffer', 'replace_subject_template', 'use_webex', 'webex_client_id', 'webex_redirect_uri'), 'id')
    else:
        platform_mjxintegration = builddict(configuration, 'platform_mjxintegration', ('name', 'description', 'end_buffer', 'ep_username', 'ep_password', 'ep_verify_certificate', 'ep_use_https', 'exchange_deployment_id', 'google_deployment_id', 'display_upcoming_meetings', 'enable_non_video_meetings', 'replace_empty_subject', 'replace_subject_type', 'enable_private_meetings', 'process_alias_private_meetings', 'start_buffer'), 'id')
    platform_mjxexchangedeployment = builddict(configuration, 'platform_mjxexchangedeployment', ('name', 'description', 'service_account_username', 'use_oauth', 'oauth_redirect_uri', 'find_items_request_quota'), 'id') #v1.1
    platform_mjxexchangedeployment_name = builddict_join(configuration, 'platform_mjxintegration', 'exchange_deployment_id', 'exchange_deployment_id', 'platform_mjxexchangedeployment', 'name') #v0.4 - fixup to prevent rare non matching (thanks @jack)
    platform_mjxexchangeautodiscoverurl = builddict(configuration, 'platform_mjxexchangeautodiscoverurl', ('name', 'description', 'url', 'exchange_deployment_id'), 'id')
    # add O364 Graph support v1.4
    if version['version-id'] >= '28':
        platform_mjxgraphdeployment = builddict(configuration, 'platform_mjxgraphdeployment', ('name', 'description', 'client_id', 'oauth_token_url', 'request_quota'), 'id')
        platform_mjxgraphdeployment_name = builddict_join(configuration, 'platform_mjxintegration', 'graph_deployment_id', 'graph_deployment_id', 'platform_mjxgraphdeployment', 'name')
    platform_mjxgoogledeployment = builddict(configuration, 'platform_mjxgoogledeployment', ('name', 'description', 'client_email', 'maximum_number_of_api_requests'), 'id')
    platform_mjxgoogledeployment_name = builddict_join(configuration, 'platform_mjxintegration', 'google_deployment_id', 'google_deployment_id', 'platform_mjxgoogledeployment', 'name')
    platform_mjxendpointgroups = builddict(configuration, 'platform_mjxendpointgroup', ('description', 'name', 'mjx_integration_id', 'system_location_id'), 'id')
    platform_mjxendpointgroup_location = builddict(configuration, 'platform_systemlocation', ('description', 'name'), 'id')
    if version['version-id'] >= '25':
        platform_mjxendpoints = builddict(configuration, 'platform_mjxendpoint', ('description', 'name', 'endpoint_type', 'api_address', 'api_port', 'api_username', 'verify_cert', 'use_https', 'mjx_endpoint_group_id', 'poly_raise_alarms_for_this_endpoint', 'poly_username', 'room_resource_email', 'webex_device_id'), 'id')
    else:
        platform_mjxendpoints = builddict(configuration, 'platform_mjxendpoint', ('description', 'name', 'endpoint_type', 'api_address', 'api_port', 'api_username', 'verify_cert', 'use_https', 'mjx_endpoint_group_id', 'poly_raise_alarms_for_this_endpoint', 'poly_username', 'room_resource_email'), 'id')
    platform_mjxmeetingprocessingrule = builddict(configuration, 'platform_mjxmeetingprocessingrule', ('name', 'description', 'priority', 'transform_rule', 'custom_template', 'enabled', 'mjx_integration_id', 'domain', 'default_processing_enabled', 'match_string', 'meeting_type'), 'id')
    if version['version-id'] >= '24':
        conferencingstatus_mjxendpoint = builddict(conferencing_status, 'conferencingstatus_mjxendpoint', ('endpoint_name', 'endpoint_type', 'endpoint_address', 'room_email', 'mjx_integration_name', 'last_worker', 'number_of_meetings', 'last_contact_time'), 'id')
        conferencingstatus_mjxmeeting = builddict(conferencing_status, 'conferencingstatus_mjxmeeting', ('subject', 'start_time', 'end_time', 'organizer_name', 'organizer_email', 'alias', 'matched_meeting_processing_rule', 'endpoint_name', 'room_email', 'mjx_integration_name', 'worker_id'), 'id')
        platform_workervm_by_ip = builddict(configuration, 'platform_workervm', ('id', 'name', 'hostname', 'alternative_fqdn', 'system_location_id', 'static_nat_address', 'secondary_address', 'maintenance_mode', 'cloud_bursting', 'transcoding', 'node_type'), 'address')
    print("Platform Version: %s (%s)" % (version['version-id'], version['pseudo-version']))
    print()
    print()
    if not platform_mjxintegration:
        print("No MJX profiles found")
        sys.exit(2)

    disabled_rules = {}
    autodiscover_svc = {} # v0.4 - change to autodiscover_svc to match non svc items
    no_endpoint_groups = {}
    no_endpoint_with_group = {}
    ms_oauth_redirect = {}

    # Loop through mjx profiles
    for mjxintegration_id in sorted(platform_mjxintegration.keys(), key=lambda k: platform_mjxintegration.keys()):
        mjx_profile_name = []
        endpoint_groups = []
        mjx = platform_mjxintegration[mjxintegration_id]
        mjx_exchange_keys = platform_mjxexchangedeployment.keys()
        mjx_exchange_autodisc_keys = platform_mjxexchangeautodiscoverurl.keys()
        if version['version-id'] >= '28': # v1.4
            mjx_graph_keys = platform_mjxgraphdeployment.keys()
        mjx_google_keys = platform_mjxgoogledeployment.keys()
        if mjx['description']:
            print("Profile #%s: %s (%s)" % (mjxintegration_id, mjx['name'], mjx['description']))
            print(len("Profile #%s: %s (%s)" % (mjxintegration_id, mjx['name'], mjx['description'])) * "=")
        else:
            print("Profile #%s: %s" % (mjxintegration_id, mjx['name']))
            print(len("Profile #%s: %s" % (mjxintegration_id, mjx['name'])) * "=")
        mjx_profile_name.append(mjx['name'])
        if display_extended == 1:
            print("> Profile Settings:")
            print("  - Start buffer: %s" % (mjx['start_buffer']))
            print("  - End buffer: %s" % (mjx['end_buffer']))
            print("  - Default API endpoint username: %s" % (mjx['ep_username']))
            print("  - Verify endpoint certificates by default: %s" % (replace(str(mjx['ep_verify_certificate']))))
            print("  - Use HTTPS for endpoint API: %s" % (replace(str(mjx['ep_use_https']))))
            print("  - No. of upcoming days: %s" % (mjx['display_upcoming_meetings']))
            print("  - Enable non-video meetings: %s" % (replace(str(mjx['enable_non_video_meetings']))))
            print("  - Enable private meetings: %s" % (replace(str(mjx['enable_private_meetings']))))
            print("  - Process alias for private meetings: %s" % (replace(str(mjx['process_alias_private_meetings']))))
            print("  - Replace subject for private meetings: %s" % (str(mjx['replace_subject_type'])))
            if version['version-id'] >= '25':
                if mjx['replace_subject_template']:
                    print("   > Replace subject string: %s" % (str(mjx['replace_subject_template'])))
                print("  - Replace empty subject: %s" % (replace(str(mjx['replace_empty_subject']))))
                print()
                print("  Cisco Webex Cloud Configuration")
                print( "  - Enable Webex Cloud: %s" % (replace(str(mjx['use_webex']))))
                if mjx['use_webex']:
                    print("  - Client ID: %s" % (str(mjx['webex_client_id'])))
                    print("  - Redirect URI: %s" % (str(mjx['webex_redirect_uri'])))
            print()

        # Exchange integration
        if mjx['exchange_deployment_id']:
            for key, item in platform_mjxexchangedeployment_name.items():
                if None not in item and key == mjx['exchange_deployment_id']:
                    mjx_exchange_desc = ''
                    for key in mjx_exchange_keys:
                        if key == mjx['exchange_deployment_id']:
                            mjx_exchange_desc = (platform_mjxexchangedeployment[key]['description'])
                            mjx_exchange_oauth = (platform_mjxexchangedeployment[key]['use_oauth'])
                            mjx_exchange_redirect = (platform_mjxexchangedeployment[key]['oauth_redirect_uri']) #v1.1
                            mjx_exchange_quota = (platform_mjxexchangedeployment[key]['find_items_request_quota'])
                            mjx_exchange_srv = (platform_mjxexchangedeployment[key]['service_account_username'])
                    if not mjx_exchange_desc:
                        mjx_exchange_desc = 'No description'
                    exchange_intergration_name = platform_mjxexchangedeployment_name[mjx['exchange_deployment_id']][0] # v0.4 - added to set name
                    print("Exchange Integration: %s (%s)" % (exchange_intergration_name, mjx_exchange_desc)) # v0.4 - remove .join
                    if display_extended == 1:
                        print("> Exchange Settings:")
                        print("  - Enable OAuth: %s" % (mjx_exchange_oauth))
                        if mjx_exchange_redirect:
                            print("  - OAuth Redirect URL: %s" % (mjx_exchange_redirect)) #v1.1
                            if 'admin/platform/mjxexchangedeployment/oauth_redirect' not in mjx_exchange_redirect:
                                ms_oauth_redirect[key] = {'exchange_name': exchange_intergration_name, 'url': mjx_exchange_redirect}
                        print("  - Find Items Request Quota: %s" % (mjx_exchange_quota))
                        print("  - Service account username: %s" % (mjx_exchange_srv))
                        for key in mjx_exchange_autodisc_keys:
                            if platform_mjxexchangeautodiscoverurl[key]['exchange_deployment_id'] == platform_mjxintegration[mjxintegration_id]['exchange_deployment_id']:
                                if platform_mjxexchangeautodiscoverurl[key]['description']:
                                    print("  - Autodiscover URL #%s: %s (%s) - %s" % (key, platform_mjxexchangeautodiscoverurl[key]['name'], platform_mjxexchangeautodiscoverurl[key]['description'], platform_mjxexchangeautodiscoverurl[key]['url']))
                                else:
                                    print("  - Autodiscover URL #%s: %s - %s" % (key, platform_mjxexchangeautodiscoverurl[key]['name'], platform_mjxexchangeautodiscoverurl[key]['url']))
                                if 'svc' not in platform_mjxexchangeautodiscoverurl[key]['url']:
                                    autodiscover_svc[key] = {'exchange_name': exchange_intergration_name, 'name': platform_mjxexchangeautodiscoverurl[key]['name'], 'url': platform_mjxexchangeautodiscoverurl[key]['url']}
                        print()

        # Graph integration v1.4
        if version['version-id'] >= '28':
            if mjx['graph_deployment_id']:
                for key, item in platform_mjxgraphdeployment_name.items():
                    if None not in item and key == mjx['graph_deployment_id']:
                        mjx_graph_desc = ''
                        for key in mjx_graph_keys:
                            if key == mjx['graph_deployment_id']:
                                mjx_graph_desc = (platform_mjxgraphdeployment[key]['description'])
                                mjx_graph_client_id = (platform_mjxgraphdeployment[key]['client_id'])
                                mjx_graph_oauth_token = (platform_mjxgraphdeployment[key]['oauth_token_url'])
                                mjx_graph_request_quota = (platform_mjxgraphdeployment[key]['request_quota'])
                        if not mjx_graph_desc:
                            mjx_graph_desc = 'No description'
                        graph_intergration_name = platform_mjxgraphdeployment_name[mjx['graph_deployment_id']][0]
                        print("Graph Integration: %s (%s)" % (graph_intergration_name, mjx_graph_desc))
                        if display_extended == 1:
                            print("> Graph Settings:")
                            print("  - Client ID: %s" % (mjx_graph_client_id))
                            print("  - OAuth 2.0 token endpoint URI: %s" % (mjx_graph_oauth_token))
                            print("  - Maximum Graph API Requests: %s" % (mjx_graph_request_quota))
                            print()

        # Google integration
        if mjx['google_deployment_id']:
            for key, item in platform_mjxgoogledeployment_name.items():
                if None not in item and key == mjx['google_deployment_id']:
                    for key in mjx_google_keys:
                        if key == mjx['google_deployment_id']:
                            mjx_google_api = (platform_mjxgoogledeployment[key]['maximum_number_of_api_requests'])
                            mjx_google_desc = (platform_mjxgoogledeployment[key]['description'])
                            mjx_google_email = (platform_mjxgoogledeployment[key]['client_email'])
                    if not mjx_google_desc:
                        mjx_google_desc = 'No description'
                    print("G Suite Integration: %s (%s)" % (', '.join(item), mjx_google_desc))
                    if display_extended == 1:
                        print("> G Suite Settings:")
                        print("  - Maximum G Suite API Requests: %s" % (mjx_google_api))
                        print("  - Service account email: %s" % (mjx_google_email))
                        print()

        # Mail integration not found (I think this is irrelevant, the UI will not let this happen?)
        if mjx['exchange_deployment_id'] not in platform_mjxexchangedeployment_name and mjx['google_deployment_id'] not in platform_mjxgoogledeployment_name:
            print("Mail Integration: *** NONE ***")
            print()

        # Endpoint groups
        if platform_mjxendpointgroups:
            for endpoint_group in sorted(platform_mjxendpointgroups.keys(), key=lambda k: platform_mjxendpointgroups[k]['name']):
                epg = platform_mjxendpointgroups[endpoint_group]
                if platform_mjxendpointgroups[endpoint_group]['mjx_integration_id'] == mjxintegration_id:
                    endpoint_groups.append(epg['name'])
        if endpoint_groups:
            print("Endpoint Groups: %s" % (', '.join(endpoint_groups)))
        else:
            no_endpoint_groups[mjxintegration_id] = {'name': mjx['name'], 'id': mjxintegration_id}
            print("Endpoint Groups: *** NONE ***")
            print()
        print()
        print()

    # Loop through endpoint groups
    for mjx_endoint_groups_id in sorted(platform_mjxendpointgroups.keys(), key=lambda k: platform_mjxendpointgroups.keys()):
        endpoints = []
        endpoint_group_id = platform_mjxendpointgroups[mjx_endoint_groups_id]
        if endpoint_group_id['description']:
            print("Endpoint Group #%s: %s (%s)" % (mjx_endoint_groups_id, endpoint_group_id['name'], endpoint_group_id['description']))
            print(len("Endpoint Group #%s: %s (%s)" % (mjx_endoint_groups_id, endpoint_group_id['name'], endpoint_group_id['description'])) * "=")
        else:
            print("Endpoint Group #%s: %s" % (mjx_endoint_groups_id, endpoint_group_id['name']))
            print(len("Endpoint Group #%s: %s" % (mjx_endoint_groups_id, endpoint_group_id['name'])) * "=")
        if display_extended == 1:
            print("> Endpoint Group Settings:")
            # output system location of endpoint group
            loc = endpoint_group_id['system_location_id']
            for key in platform_mjxendpointgroup_location:
                if loc == key:
                    system_location = platform_mjxendpointgroup_location[key]['name']
            print("  - System location: %s" % (system_location))

        if display_endpoints:
            if platform_mjxendpoints:
                if version['version-id'] >= '25':
                    header = ['Name', 'Type', 'Room Resource Email', 'Use HTTPS', 'Verify Certificate', 'API Address', 'Raise Alarms', 'Webex Device ID']
                else:
                    header = ['Name', 'Type', 'Room Resource Email', 'Use HTTPS', 'Verify Certificate', 'API Address']
                endpoint_data = [header]
                for endpoint in sorted(platform_mjxendpoints.keys(), key=lambda k: platform_mjxendpoints[k]['name']):
                    if platform_mjxendpoints[endpoint]['api_port']:
                        ep_api_address = str(platform_mjxendpoints[endpoint]['api_address'])+':'+str(platform_mjxendpoints[endpoint]['api_port'])
                    else:
                        ep_api_address = platform_mjxendpoints[endpoint]['api_address']
                    if platform_mjxendpoints[endpoint]['description']:
                        platform_mjxendpoints[endpoint]['description'] = '('+platform_mjxendpoints[endpoint]['description']+')'
                    if platform_mjxendpoints[endpoint]['endpoint_type'] == 'CISCO':
                        platform_mjxendpoints[endpoint]['endpoint_type'] = 'Cisco OBTP'
                    if platform_mjxendpoints[endpoint]['endpoint_type'] == 'POLY':
                        platform_mjxendpoints[endpoint]['endpoint_type'] = 'Poly OTD'
                    if version['version-id'] >= '25':
                        if platform_mjxendpoints[endpoint]['endpoint_type'] == 'WEBEX':
                            platform_mjxendpoints[endpoint]['endpoint_type'] = 'Cisco Webex Cloud'
                    if ep_api_address:
                        ep_api_address = (ep_api_address[:35] + '..') if len(ep_api_address) > 37 else ep_api_address
                    platform_mjxendpoints[endpoint]['name'] = (platform_mjxendpoints[endpoint]['name'][:35] + '..') if len(platform_mjxendpoints[endpoint]['name']) > 37 else platform_mjxendpoints[endpoint]['name']
                    platform_mjxendpoints[endpoint]['room_resource_email'] = (platform_mjxendpoints[endpoint]['room_resource_email'][:35] + '..') if len(platform_mjxendpoints[endpoint]['room_resource_email']) > 37 else platform_mjxendpoints[endpoint]['room_resource_email']
                    if version['version-id'] >= '25':
                        platform_mjxendpoints[endpoint]['poly_raise_alarms_for_this_endpoint'] = replace(str(platform_mjxendpoints[endpoint]['poly_raise_alarms_for_this_endpoint']))
                        platform_mjxendpoints[endpoint]['webex_device_id'] = platform_mjxendpoints[endpoint]['webex_device_id']
                    endpoint_detail = platform_mjxendpoints[endpoint]
                    if platform_mjxendpoints[endpoint]['mjx_endpoint_group_id'] == mjx_endoint_groups_id:
                        if version['version-id'] >= '25':
                            endpoints = [endpoint_detail['name'], endpoint_detail['endpoint_type'], endpoint_detail['room_resource_email'], replace(endpoint_detail['use_https']).capitalize(), replace(endpoint_detail['verify_cert']).capitalize(), ep_api_address, platform_mjxendpoints[endpoint]['poly_raise_alarms_for_this_endpoint'], platform_mjxendpoints[endpoint]['webex_device_id']]
                        else:
                            endpoints = [endpoint_detail['name'], endpoint_detail['endpoint_type'], endpoint_detail['room_resource_email'], replace(endpoint_detail['use_https']).capitalize(), replace(endpoint_detail['verify_cert']).capitalize(), ep_api_address]
                        endpoint_data.append(endpoints)
                    if not platform_mjxendpoints[endpoint]['mjx_endpoint_group_id']:
                        no_endpoint_with_group[endpoint] = {'name': platform_mjxendpoints[endpoint]['name'], 'type': endpoint_detail['endpoint_type']}
            if endpoints:
                print()
                print("Endpoints: %d" % (len(endpoint_data)-1))
                print
                tabulate(endpoint_data)
            else:
                print()
                print("Endpoints: *** NONE ***")
        print()
        print()

    # Get/print status information
    if display_status_items:
        if version['version-id'] < '24':
            pass
        else:
            endpoints = []
            print("OTJ Endpoint Status")
            print(len("OTJ Endpoint Status") * "=")
            print()
            epstatus_header = ['Name', 'Type', 'Address', 'Email', 'OTJ Profile', 'Meetings', 'Current Node', 'Last Contacted']
            epstatus_data = [epstatus_header]
            for key, endpoint in sorted(conferencingstatus_mjxendpoint.items()):
                worker = get_worker(platform_workervm_by_ip, endpoint['last_worker'])
                endpoints = endpoint['endpoint_name'], endpoint['endpoint_type'], endpoint['endpoint_address'], endpoint['room_email'][:35] + '..' if len(endpoint['room_email']) > 37 else endpoint['room_email'], endpoint['mjx_integration_name'], endpoint['number_of_meetings'], worker if worker else None, endpoint['last_contact_time']
                epstatus_data.append(endpoints)
            if endpoints:
                tabulate(epstatus_data)
            else:
                print('No endpoint data was found')
            print()
            print()
            print("OTJ Meetings")
            print(len("OTJ Meetings") * "=")
            print()
            mjxmeeting_header = ['Subject', 'Organizer email', 'Start Time', 'End Time', 'Endpoint', 'OTJ Profile', 'Matched Processing Rule', 'Meeting Alias']
            mjxmeeting_data = [mjxmeeting_header]
            for key, meeting in conferencingstatus_mjxmeeting.items():
                meeting['subject'] = meeting['subject'][:25] if len(meeting['subject']) > 26 else meeting['subject']
                meetings = meeting['subject'], meeting['organizer_email'][:35] + '..' if len(meeting['organizer_email']) > 37 else meeting['organizer_email'], meeting['start_time'], meeting['end_time'], meeting['endpoint_name'], meeting['mjx_integration_name'], meeting['matched_meeting_processing_rule'], meeting['alias'][:35] + '..' if len(meeting['alias']) > 37 else meeting['alias']
                mjxmeeting_data.append(meetings)
            if meetings:
                tabulate(mjxmeeting_data)
            else:
                print('No meeting data was found')
            print()
            print()

    # Loop through meeting processing rules
    if platform_mjxmeetingprocessingrule:
        print("Meeting Processing Rules (Sorted by priority)")
        print(len("Meeting Processing Rules (Sorted by priority)") * "=")
        print()
        for platform_mjxmeetingprocessingrule_id in sorted(platform_mjxmeetingprocessingrule.keys(), key=lambda k: platform_mjxmeetingprocessingrule[k]['priority']):
            rules = platform_mjxmeetingprocessingrule[platform_mjxmeetingprocessingrule_id]
            populated_keys_list = [key for key, value in rules.items() if value] # we don't want any empty key,value pairs
            excluded_keys = ['custom_template', 'mjx_integration_id', 'name', 'priority'] # exclude the keys we are specifically formatting the output for
            custom_template_detail = ''
            print("Rule #%s (Priority #%s)" % (platform_mjxmeetingprocessingrule_id, rules['priority']))
            if rules['description']:
                print(" > Name: %s (%s)" % (rules['name'], rules['description']))
            else:
                print(" > Name: %s" % (rules['name']))
            for key, value in rules.items():
                if key == 'enabled' and value == 0:
                    disabled_rules[platform_mjxmeetingprocessingrule_id] = {'priority': rules['priority'], 'name': rules['name']}
                if key in populated_keys_list:
                    if key == 'custom_template': # save and print out the custom template last
                        custom_template_detail = value
                    if key == 'mjx_integration_id':
                        for mjxintegration_id in sorted(platform_mjxintegration.keys(), key=lambda k: platform_mjxintegration[k]['name']):
                            if rules['mjx_integration_id'] == mjxintegration_id:
                                mjx = platform_mjxintegration[mjxintegration_id]
                        print("   - Profile: %s" % (mjx['name']))
                    if key in excluded_keys:
                        continue
                    if isinstance(value, int):
                        value = replace(str(value))
                    print('   - %s: %s' % (replace(key).capitalize(), value))
            if custom_template_detail:
                print( "   - Custom Template:")
                for line in custom_template_detail.splitlines():
                    print('\t'+line)
            print()
        print()

    # Spit out any potential issues
    if disabled_rules or autodiscover_svc or no_endpoint_groups or no_endpoint_with_group or ms_oauth_redirect:
        print("Potential Configuration Issues")
        print(len("Potential Configuration Issues") * "=")
        print()
        if disabled_rules:
            print('The following meeting processing rules are disabled')
            for key, value in disabled_rules.items():
                print(' - %s (Priority: #%s)' % (value['name'], value['priority']))
            print()
        if autodiscover_svc: # v0.4 - updated block
            print('The following Exchange deployments are not configured with a svc autodiscover URL')
            for key, value in autodiscover_svc.items():
                print(' - %s - Autodiscover URL: %s (%s)' % (value['exchange_name'], value['name'], value['url']))
            print()
        if ms_oauth_redirect: # v1.1
            print('The following Exchange deployments are configured with an incorrect OAuth Redirect URL')
            for key, value in ms_oauth_redirect.items():
                print(' - %s - OAuth Redirect URL: %s' % (value['exchange_name'], value['url']))
            print()
        if no_endpoint_with_group:
            print('The following endpoints have no group associated')
            for key, value in no_endpoint_with_group.items():
                print(' - %s (%s)' % (value['name'], value['type']))
            print()
        if no_endpoint_groups:
            print('The following MJX profiles have no endpoint groups associated')
            for key, value in no_endpoint_groups.items():
                print(' - Profile #%s: %s' % (value['id'], value['name']))
            print()
        print()

    # Check active alarms
    mjx_alarms = {}
    if platformstatus_alarm: # 0.5 - added
        for key, item in platformstatus_alarm.items():
            if 'mjx' in item['name']:
                mjx_alarms[key] = item
        if mjx_alarms:
            print("Active alarms (MJX)")
            print(len("Active alarms (MJX)") * "=")
            for key, value in mjx_alarms.items():
                print(' > Alarm #%s' % (key))
                print('   - Name: %s' % (value['name']))
                print('   - Details: %s' % (value['details']))
                print('   - Node: %s' % (value['node']))
                print('   - Instance: %s' % (value['instance']))
                print('   - Time raised: %s' % (value['time_raised']))
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
            print("Usage: %s <snapshot folder>" % (os.path.basename(__file__)))
    except (IOError, KeyboardInterrupt):
        pass
