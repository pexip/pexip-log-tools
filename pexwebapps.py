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

# Webapp path based branding output
#
# Disable "Invalid constant name"                       pylint: disable=C0103
# Disable "Line too long"                               pylint: disable=C0301
# Disable "Missing docstring"                           pylint: disable=C0111
# Disable "No exception type(s) specified"              pylint: disable=W0702
# Disable "Module 'sqlite3' has no member"              pylint: disable=E1101
import json
import os
import sqlite3
import sys

def builddict(db, table, fields, key):
    resp = {}
    cur = db.cursor()
    cur.execute('select * from %s' % table)
    for row in cur:
        data = {}
        for field in fields:
            data[field] = row[field] if field in row.keys() else '0'
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
            if os.name == 'nt':
                print(str(row[ind]).encode('cp850', errors='replace').decode('cp850'), end=" ")
            else:
                print(str(row[ind]), end=" ")
            print(" " * (lengths[ind] - len(str(row[ind]))), end=" ")
        print("")

def main(rootdir):
    """Main processing"""
    try:
        configuration = sqlite3.connect(os.path.join(rootdir, 'opt/pexip/share/config/conferencing_configuration.db'))
        configuration.row_factory = sqlite3.Row
        if os.path.exists(os.path.join(rootdir, 'opt/pexip/lib/python2.7/site-packages/si/web/management/conf/static/version.json')):
            version = json.load(open(os.path.join(rootdir, 'opt/pexip/lib/python2.7/site-packages/si/web/management/conf/static/version.json'), 'r'))
        else:
            version = json.load(open(os.path.join(rootdir, 'opt/pexip/share/web/static/version/version.json'), 'r'))
    except:
        print('FATAL: Unable to open database files')
        print('Usage: %s <snapshot folder>' % (os.path.basename(__file__)))
        sys.exit(2)
    if version['version-id'] < '31':
        print("FATAL: Requires Pexip Infinity version 31 or higher")
        sys.exit(2)
    platform_global = builddict(configuration, 'platform_global', ('id', 'default_webapp_alias_id'), 'id')
    platform_softwarebundle = builddict(configuration, 'platform_softwarebundle', ('id', 'revision', 'version', 'package', 'filename', 'core', 'bundle_type'), 'id')
    platform_softwarebundleselectedrevisions = builddict(configuration, 'platform_softwarebundleselectedrevisions', ('id', 'bundle_type', 'selected_revision_id'), 'id')
    platform_webappalias = builddict(configuration, 'platform_webappalias', ('id', 'slug', 'webapp_type', 'is_enabled', 'branding_id', 'bundle_id', 'description'), 'id')
    platform_webappbrandingpackage = builddict(configuration, 'platform_webappbrandingpackage', ('uuid', 'webapp_type', 'name', 'last_updated', 'is_default', 'description'), 'uuid')

    webappswbundles_header = ['ID', 'Bundle Type', 'Package', 'Revision', 'Version', 'Filename', 'Core']
    webappswbundles_data = [webappswbundles_header]
    webappswbundlerevisions_header = ['ID', 'Bundle Type', 'Selected Revision ID', 'Selected Revision Type', 'Selected Revision Package']
    webappswbundlerevisions_data = [webappswbundlerevisions_header]
    webapppath_header = ['ID', 'Slug', 'Webapp Type', 'Enabled', 'Default Path', 'Branding UUID', 'Branding Name', 'Software Bundle ID', 'Description']
    webapppath_data = [webapppath_header]
    webappbrand_header = ['Name', 'Description', 'Default', 'Webapp Type', 'Last Updated', 'UUID']
    webappbrand_data = [webappbrand_header]

    print("Platform Version: %s (%s)" % (version['version-id'], version['pseudo-version']))
    print()
    print("Webapp Paths")
    print(len("Webapp Paths") * "=")
    for globalsetting in sorted(platform_global.keys(), key=lambda k: platform_global.keys()):
        is_default = platform_global[globalsetting]['default_webapp_alias_id']
    for webapppath in sorted(platform_webappalias.keys(), key=lambda k: platform_webappalias.keys()):
        branding_name = ''
        if platform_webappalias[webapppath]['id'] == is_default:
            default_path = 'Yes'
        else:
            default_path = 'No'
        for webappbrand in sorted(platform_webappbrandingpackage.keys(), key=lambda k: platform_webappbrandingpackage.keys()):
            if platform_webappbrandingpackage[webappbrand]['uuid'] == platform_webappalias[webapppath]['branding_id']:
                branding_name = platform_webappbrandingpackage[webappbrand]['name']
            if not platform_webappalias[webapppath]['branding_id']:
                if platform_webappalias[webapppath]['webapp_type'] == platform_webappbrandingpackage[webappbrand]['webapp_type'] and platform_webappbrandingpackage[webappbrand]['is_default'] == 1:
                    platform_webappalias[webapppath]['branding_id'] = platform_webappbrandingpackage[webappbrand]['uuid']
                    branding_name = platform_webappbrandingpackage[webappbrand]['name']
        webappalias = [platform_webappalias[webapppath]['id'], platform_webappalias[webapppath]['slug'], platform_webappalias[webapppath]['webapp_type'], str(platform_webappalias[webapppath]['is_enabled']).replace('0', 'No').replace('1', 'Yes'), default_path, platform_webappalias[webapppath]['branding_id'], branding_name, platform_webappalias[webapppath]['bundle_id'], platform_webappalias[webapppath]['description']]
        webapppath_data.append(webappalias)
    tabulate(webapppath_data)
    print()
    print("Webapp Branding")
    print(len("Webapp Branding") * "=")
    for webappbrand in sorted(platform_webappbrandingpackage.keys(), key=lambda k: platform_webappbrandingpackage[k]['name']):
        webappbrands = platform_webappbrandingpackage[webappbrand]['name'], platform_webappbrandingpackage[webappbrand]['description'], str(platform_webappbrandingpackage[webappbrand]['is_default']).replace('0', 'No').replace('1', 'Yes'), platform_webappbrandingpackage[webappbrand]['webapp_type'], platform_webappbrandingpackage[webappbrand]['last_updated'], platform_webappbrandingpackage[webappbrand]['uuid']
        webappbrand_data.append(webappbrands)
    tabulate(webappbrand_data)
    print()
    print("Webapp Software Bundles")
    print(len("Webapp Software Bundles") * "=")
    for webappbundle in sorted(platform_softwarebundle.keys(), key=lambda k: platform_softwarebundle.keys()):
        if platform_softwarebundle[webappbundle]['bundle_type'] != 'pexrtc':
            webappbundles = platform_softwarebundle[webappbundle]['id'], platform_softwarebundle[webappbundle]['bundle_type'], platform_softwarebundle[webappbundle]['package'], platform_softwarebundle[webappbundle]['revision'], platform_softwarebundle[webappbundle]['version'], platform_softwarebundle[webappbundle]['filename'], str(platform_softwarebundle[webappbundle]['core']).replace('0', 'No').replace('1', 'Yes')
            webappswbundles_data.append(webappbundles)
    tabulate(webappswbundles_data)
    print()
    print("Webapp Software Bundle Selected Revisions")
    print(len("Webapp Software Bundle Selected Revisions") * "=")
    for webappbundlerevision in sorted(platform_softwarebundleselectedrevisions.keys(), key=lambda k: platform_softwarebundleselectedrevisions[k]['bundle_type']):
        bundlename = ''
        bundletype = ''
        if platform_softwarebundleselectedrevisions[webappbundlerevision]['bundle_type'] != 'pexrtc':
            for webappbundle in sorted(platform_softwarebundle.keys(), key=lambda k: platform_softwarebundle.keys()):
                if platform_softwarebundleselectedrevisions[webappbundlerevision]['selected_revision_id'] == platform_softwarebundle[webappbundle]['id']:
                    bundlename = platform_softwarebundle[webappbundle]['package']
                    bundletype = platform_softwarebundle[webappbundle]['bundle_type']
            webappbundlerevisions = platform_softwarebundleselectedrevisions[webappbundlerevision]['id'], platform_softwarebundleselectedrevisions[webappbundlerevision]['bundle_type'], platform_softwarebundleselectedrevisions[webappbundlerevision]['selected_revision_id'], bundletype, bundlename
            webappswbundlerevisions_data.append(webappbundlerevisions)
    tabulate(webappswbundlerevisions_data)
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
        pass
