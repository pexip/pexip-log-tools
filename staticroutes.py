#!/usr/bin/env python3
# get_routes: print static route detail
#
# v0.4 # remove dbsummary dependency
# v0.3 # port to python3
# v0.2 # fix dns and ntp issue if fqdn was used
#
# Disable "Line too long"                               pylint: disable=C0301
# Disable "Missing docstring"                           pylint: disable=C0111
# Disable "Too many branches"                           pylint: disable=R0912
# Disable "Too many statements"                         pylint: disable=R0915
# Disable "Access to a protected member"                pylint: disable=W0212
import ipaddress
import os
import sqlite3
import sys

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
    dual_nic_found = 0
    s_route_num = 1
    try:
        configuration = sqlite3.connect(os.path.join(rootdir, 'opt/pexip/share/config/conferencing_configuration.db'))
        configuration.row_factory = sqlite3.Row
    except:
        print("FATAL: Unable to open database files")
        print("Usage: %s <snapshot folder>" % (os.path.basename(__file__)))
        sys.exit(2)
    platform_managementvm_by_ip = builddict(configuration, 'platform_managementvm', ('id', 'name', 'hostname', 'address'), 'address')
    platform_workervm_by_ip = builddict(configuration, 'platform_workervm', ('id', 'name', 'hostname', 'alternative_fqdn', 'system_location_id', 'static_nat_address', 'secondary_address', 'secondary_netmask', 'maintenance_mode', 'cloud_bursting', 'transcoding', 'node_type', 'netmask', 'gateway'), 'address')
    platform_dnsserver_by_ip = builddict(configuration, 'platform_dnsserver', ('id', 'address'), 'address')
    platform_ntpserver_by_ip = builddict(configuration, 'platform_ntpserver', ('id', 'address'), 'address')
    platform_syslogserver_by_ip = builddict(configuration, 'platform_syslogserver', ('id', 'address'), 'address')
    platform_workervm_static_routes = builddict(configuration, 'platform_workervm_static_routes', ('id', 'workervm_id', 'staticroute_id'), 'id')
    platform_staticroute = builddict(configuration, 'platform_staticroute', ('id', 'name', 'address', 'prefix', 'gateway'), 'id')
    print("Static route configuration for dual interface nodes")
    print()
    header = ['Primary IP', 'Primary Mask', 'Secondary IP', 'Secondary Mask', 'Static NAT', 'Gateway']
    network_data = [header]
    for worker in sorted(platform_workervm_by_ip.keys(), key=lambda k: platform_workervm_by_ip[k]['name']):
        matched_static_routes = []
        if platform_workervm_by_ip[worker]['secondary_address'] is not None:
            dual_nic_found = 1
            print(platform_workervm_by_ip[worker]['name'])
            print(len(platform_workervm_by_ip[worker]['name']) * "=")
            networks = [worker, platform_workervm_by_ip[worker]['netmask'], platform_workervm_by_ip[worker]['secondary_address'], platform_workervm_by_ip[worker]['secondary_netmask'], platform_workervm_by_ip[worker]['static_nat_address'], platform_workervm_by_ip[worker]['gateway']]
            network_data.append(networks)
            if platform_workervm_by_ip[worker]['static_nat_address']:
                print('static nat:\t%s' % (platform_workervm_by_ip[worker]['static_nat_address']))
                print()
            for key, route in platform_workervm_static_routes.items():
                if platform_workervm_by_ip[worker]['id'] == route['workervm_id']:
                    for key, static_route in sorted(platform_staticroute.items(), key=lambda k: platform_staticroute.items()):
                        if key == route['staticroute_id']:
                            matched_static_routes.append((static_route['address'], static_route['prefix'], static_route['gateway']))
            tabulate(network_data)
            print()
            print("Static routes applied to %s" % (platform_workervm_by_ip[worker]['name']))
            print(len("Static routes applied to %s" % (platform_workervm_by_ip[worker]['name'])) * "=")
            for s_route in matched_static_routes:
                print('#%s - %s/%s via %s' % (s_route_num, s_route[0], s_route[1], s_route[2]))
                # match against management node
                manager_vm = []
                for manager in sorted(platform_managementvm_by_ip.keys(), key=lambda k: platform_managementvm_by_ip[k]['name']):
                    if ipaddress.ip_address(manager) in ipaddress.ip_network('%s/%s' % (s_route[0], s_route[1])):
                        manager_vm.append(('%s (%s)' % (platform_managementvm_by_ip[manager]['name'], 'Manager')))
                if manager_vm:
                    print(" - Routing to: %s" % ', '.join(manager_vm))
                # match against worker nodes
                nodes = []
                for worker in sorted(platform_workervm_by_ip.keys(), key=lambda k: platform_workervm_by_ip[k]['name']):
                    if ipaddress.ip_address(worker) in ipaddress.ip_network('%s/%s' % (s_route[0], s_route[1])):
                        nodes.append(('%s (%s)' % (platform_workervm_by_ip[worker]['name'], platform_workervm_by_ip[worker]['node_type'].lower().capitalize())))
                if nodes:
                    print(" - Routing to: %s" % ', '.join(nodes))
                # match against dns servers
                dns_servers = []
                for dns in sorted(platform_dnsserver_by_ip.keys(), key=lambda k: platform_dnsserver_by_ip[k]['id']):
                    try:
                        if ipaddress.ip_address(dns) in ipaddress.ip_network('%s/%s' % (s_route[0], s_route[1])):
                            dns_servers.append(('%s (%s)' % (platform_dnsserver_by_ip[dns]['address'], 'DNS')))
                    except:
                        pass
                if dns_servers:
                    print(" - Routing to: %s" % ', '.join(dns_servers))
                # match against ntp servers
                ntp_servers = []
                for ntp in sorted(platform_ntpserver_by_ip.keys(), key=lambda k: platform_ntpserver_by_ip[k]['id']):
                    try:
                        if ipaddress.ip_address(ntp) in ipaddress.ip_network('%s/%s' % (s_route[0], s_route[1])):
                            ntp_servers.append(('%s (%s)' % (platform_ntpserver_by_ip[ntp]['address'], 'NTP')))
                    except:
                        pass
                if ntp_servers:
                    print(" - Routing to: %s" % ', '.join(ntp_servers))
                # match against syslog servers
                syslog_servers = []
                for syslog in sorted(platform_syslogserver_by_ip.keys(), key=lambda k: platform_syslogserver_by_ip[k]['id']):
                    try:
                        if ipaddress.ip_address(syslog) in ipaddress.ip_network('%s/%s' % (s_route[0], s_route[1])):
                            syslog_servers.append(('%s (%s)' % (platform_syslogserver_by_ip[syslog]['address'], 'Syslog')))
                    except:
                        pass
                if syslog_servers:
                    print(" - Routing to: %s" % ', '.join(syslog_servers))
                s_route_num += 1
            print("\n")
            network_data = [header]
        s_route_num = 1
    if not dual_nic_found:
        print('No dual interface nodes found')

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
