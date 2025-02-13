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
USAGE:

pexidpconfig.py <snapshot folder>

This script outputs the IdP configuration of a Pexip snapshot.
"""

import argparse
import json
import os
import sqlite3
import sys

# pylint: disable=missing-class-docstring
# pylint: disable=line-too-long
# pylint: disable=bare-except
# pylint: disable=expression-not-assigned

class PexIdPConfig:
    """PexAuth class for managing Pexip IdP configuration"""

    def __init__(self, rootdir):
        """
        Initialize PexAuth object.

        Args:
            rootdir (str): The root directory of the Pexip snapshot.

        Raises:
            sqlite3.OperationalError: If there is an error connecting to the SQLite database.
        """
        try:
            self.configurationdb = sqlite3.connect(os.path.join(rootdir, 'opt/pexip/share/config/conferencing_configuration.db'))
            self.configurationdb.row_factory = sqlite3.Row
        except sqlite3.OperationalError as e:
            print(f'FATAL: {e}')
            print(f'Usage: {(os.path.basename(__file__))} <snapshot folder>')
            sys.exit(2)
        if os.path.exists(os.path.join(rootdir, 'opt/pexip/lib/python2.7/site-packages/si/web/management/conf/static/version.json')):
            self.version = json.load(open(os.path.join(rootdir, 'opt/pexip/lib/python2.7/site-packages/si/web/management/conf/static/version.json'), 'r', encoding='utf-8'))
        else:
            self.version = json.load(open(os.path.join(rootdir, 'opt/pexip/share/web/static/version/version.json'), 'r', encoding='utf-8'))
        if self.version['major'] <= 26:
            print('This script is only compatible with version 27 or higher')
            sys.exit(2)
        if self.version['major'] <= 29:
            self.platform_identityprovider_table = self._build_dict(self.configurationdb, 'platform_identityprovider', ('id', 'name', 'description', 'uuid', 'sso_url', 'display_name_attribute_name', 'service_entity_id', 'idp_entity_id', 'digest_algorithm', 'assertion_consumer_service_url', 'assertion_consumer_service_url1', 'assertion_consumer_service_url2', 'assertion_consumer_service_url3', 'assertion_consumer_service_url4', 'assertion_consumer_service_url5', 'assertion_consumer_service_url6', 'assertion_consumer_service_url7', 'assertion_consumer_service_url8', 'assertion_consumer_service_url9', 'assertion_consumer_service_url10', 'worker_fqdn_acs_urls'), 'id')
        else:
            self.platform_identityprovider_table = self._build_dict(self.configurationdb, 'platform_identityprovider', ('id', 'name', 'description', 'uuid', 'sso_url', 'display_name_attribute_name', 'service_entity_id', 'idp_entity_id', 'digest_algorithm', 'assertion_consumer_service_url', 'assertion_consumer_service_url1', 'assertion_consumer_service_url2', 'assertion_consumer_service_url3', 'assertion_consumer_service_url4', 'assertion_consumer_service_url5', 'assertion_consumer_service_url6', 'assertion_consumer_service_url7', 'assertion_consumer_service_url8', 'assertion_consumer_service_url9', 'assertion_consumer_service_url10', 'worker_fqdn_acs_urls', 'idp_type', 'oidc_client_id', 'oidc_display_name_claim_name', 'oidc_jwks_url', 'oidc_token_endpoint_auth_scheme', 'oidc_token_url', 'oidc_client_secret', 'oidc_france_connect_required_eidas_level', 'oidc_token_signature_scheme', 'oidc_user_info_url', 'oidc_flow'), 'id')
        if self.version['major'] >= 33:
            self.platform_identityprovider_attributes_table_join = self._build_dict_join(self.configurationdb, 'platform_identityprovider_attributes', 'identityprovider_id', 'identityproviderattribute_id', 'platform_identityproviderattribute', 'name')
        self.platform_identityprovider_group_table = self._build_dict(self.configurationdb, 'platform_identityprovidergroup', ('id', 'name', 'description'), 'id')
        self.platform_identityprovidergroup_identity_provider_table_join = self._build_dict_join(self.configurationdb, 'platform_identityprovidergroup_identity_provider', 'identityprovidergroup_id', 'identityprovider_id', 'platform_identityprovider', 'name')
        self.conferencing_conference_table = self._build_dict(self.configurationdb, 'conferencing_conference', ('id', 'name', 'guest_identity_provider_group_id', 'host_identity_provider_group_id'), 'id')
        self.conferencing_conference_table_join = self._build_dict_join(self.configurationdb, 'platform_identityprovidergroup_identity_provider', 'identityprovidergroup_id', 'identityprovider_id', 'conferencing_conference', 'name')


    def _build_dict(self, db, table, fields, key):
        """
        Build a dictionary from a SQLite table.

        Args:
            db (sqlite3.Connection): The SQLite database connection.
            table (str): The name of the table.
            fields (tuple): The fields to include in the dictionary.
            key (str): The key field to use as the dictionary key.

        Returns:
            dict: The dictionary built from the table.
        """
        resp = {}
        cur = db.cursor()
        cur.execute(f'select * from {table}')
        for row in cur:
            data = {}
            for field in fields:
                data[field] = row[field] if field in row.keys() else ''
            resp[row[key]] = data
        return resp


    def _build_dict_join(self, db, join_table, join_index, join_field, table, field):
        """
        Build a dictionary with joined tables.

        Args:
            db (sqlite3.Connection): The SQLite database connection.
            join_table (str): The name of the join table.
            join_index (str): The index field in the join table.
            join_field (str): The field in the join table to join on.
            table (str): The name of the table to join.
            field (str): The field in the table to join on.

        Returns:
            dict: The dictionary built from the join tables.
        """
        resp = {}
        cur = db.cursor()
        cur.execute(f'select {join_table}.{join_index} as {join_index}, {table}.{field} as {field} from {join_table} left join {table} on {join_table}.{join_field} == {table}.id')
        for row in cur:
            if row[join_index] in resp:
                resp[row[join_index]].append(row[field])
            else:
                resp[row[join_index]] = [row[field]]
        return resp


    def print_idp_config(self):
        """
        Print the IdP configuration.
        """
        if not self.platform_identityprovider_table:
            print('No identity providers configured')
            return
        auth_config = self.platform_identityprovider_table
        additional_consumers = []
        print(f'Platform Version: {self.version["version-id"]} ({self.version["pseudo-version"]})')
        print()
        for idx, provider in enumerate(auth_config.values(), start=1):
            for key, value in provider.items():
                if key.startswith('assertion_consumer_service_url') and value:
                    additional_consumers.append(value)
            additional_consumers.pop(0)
            print(f'Identity Provider #{idx} - {provider["name"]} ({provider["description"]})') if provider["description"] else print(f'Identity Provider #{idx} - {provider["name"]}')
            print(len(f'Identity Provider #{idx} - {provider["name"]} ({provider["description"]})') * '=') if provider["description"] else print(len(f'Identity Provider #{idx} - {provider["name"]}') * '=')
            if 'saml' in provider['idp_type']:
                print('> Service Configuration')
                print(f'  - Type: {provider["idp_type"].upper()}')
                print(f'  - UUID: {provider["uuid"]}')
                print(f'  - Redirect URL: {provider["assertion_consumer_service_url"]}')
                print(f'  - SAML 2.0 entity ID: {provider["service_entity_id"]}')
                print(f'  - Signature algorithm: {provider["oidc_token_signature_scheme"]}')
                print(f'  - Digest algorithm: {provider["digest_algorithm"].split("#")[-1]}')
                print()
            else:
                print('> Service Configuration')
                print(f'  - Type: {provider["idp_type"].upper()}')
                print(f'  - UUID: {provider["uuid"]}')
                print(f'  - Redirect URL: {provider["assertion_consumer_service_url"]}')
                print(f'  - OIDC flow: {provider["oidc_flow"]}')
                print(f'  - OIDC client ID: {provider["oidc_client_id"]}')
                print()
                print(f'  - OIDC token endpoint auth type: {provider["oidc_token_endpoint_auth_scheme"]}')
                print(f'  - OIDC token signature scheme: {provider["oidc_token_signature_scheme"]}')
                print(f'  - OIDC user info endpoint URL: {provider["oidc_user_info_url"]}')
                print(f'  - OIDC France Connect required EIDAS Level: {provider["oidc_france_connect_required_eidas_level"].capitalize()}')
                print()
            if additional_consumers:
                print(f'> Additional redirect URLs ({len(additional_consumers)}):')
                for consumer in additional_consumers:
                    print(f'  - {consumer}')
                print()
            print('> Identity Provider Configuration')
            print(f'  - SSO URL: {provider["sso_url"]}')
            if 'oidc' in provider['idp_type']:
                print(f'  - OIDC token endpoint URL: {provider["oidc_token_url"]}')
                print(f'  - OIDC JWKS URL: {provider["oidc_jwks_url"]}')
            print(f'  - Entity ID: {provider["idp_entity_id"]}')
            if 'oidc' in provider['idp_type']:
                print(f'  - OIDC display name claim name: {provider["oidc_display_name_claim_name"]}')
            else:
                print(f'  - Display name attribute: {provider["display_name_attribute_name"]}')
            print()
            additional_consumers = []
            if self.version['major'] >= 33:
                try:
                    print(f'> Attributes ({len(self.platform_identityprovider_attributes_table_join[provider["id"]])}): {", ".join(self.platform_identityprovider_attributes_table_join[provider["id"]])}')
                    print()
                except:
                    pass
        print('Identity Provider Groups')
        print(len('Identity Provider Groups') * '=')
        print()
        services = []
        for idx, group in enumerate(self.platform_identityprovider_group_table.values(), start=1):
            print(f'> Identity Provider Group #{idx} - {group["name"]} ({group["description"]})') if group["description"] else print(f'> Identity Provider Group #{idx} - {group["name"]}')
            print(f'  - Identity Providers ({len(self.platform_identityprovidergroup_identity_provider_table_join[group["id"]])}): {", ".join(self.platform_identityprovidergroup_identity_provider_table_join[group["id"]])}')
            for service in self.conferencing_conference_table:
                if self.conferencing_conference_table[service]['guest_identity_provider_group_id'] == group['id'] or self.conferencing_conference_table[service]['host_identity_provider_group_id'] == group['id']:
                    services.append(self.conferencing_conference_table[service]['name'])
            if services:
                print(f'  - Configured Services ({len(services)}): {", ".join(services)}')
                services = []
            print()
        self.configurationdb.close()


def main():
    """Main processing"""
    parser = argparse.ArgumentParser(description='Output the IdP configuration of the management node')
    parser.add_argument('snapshot', help='Snapshot folder')
    args = parser.parse_args()

    process_snapshot = PexIdPConfig(args.snapshot)
    process_snapshot.print_idp_config()


if __name__ == "__main__":
    main()
