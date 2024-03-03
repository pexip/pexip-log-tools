#!/usr/bin/env python3

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

"""
USAGE:

pexauthconfig.py <snapshot folder>

This script outputs the authentication configuration of a Pexip snapshot.
"""

import argparse
import json
import os
import sqlite3
import sys

# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring
# pylint: disable=line-too-long

class PexAuth:
    """PexAuth class for managing Pexip authentication configuration"""

    def __init__(self, rootdir):
        """
        Initialize PexAuth object.

        Args:
            rootdir (str): The root directory of the Pexip snapshot.

        Raises:
            sqlite3.OperationalError: If there is an error connecting to the SQLite database.
        """
        try:
            self.defaultdb = sqlite3.connect(os.path.join(rootdir, 'opt/pexip/share/config/default.db'))
            self.defaultdb.row_factory = sqlite3.Row
        except sqlite3.OperationalError as e:
            print(f"FATAL: {e}")
            print(f"Usage: {(os.path.basename(__file__))} <snapshot folder>")
            sys.exit(2)
        if os.path.exists(os.path.join(rootdir, 'opt/pexip/lib/python2.7/site-packages/si/web/management/conf/static/version.json')):
            self.version = json.load(open(os.path.join(rootdir, 'opt/pexip/lib/python2.7/site-packages/si/web/management/conf/static/version.json'), 'r', encoding='utf-8'))
        else:
            self.version = json.load(open(os.path.join(rootdir, 'opt/pexip/share/web/static/version/version.json'), 'r', encoding='utf-8'))
        if self.version['version-id'] <= '24':
            print('This script is only compatible with version 24 or higher')
            sys.exit(2)
        self.permissions_authentication_table = self._build_dict(self.defaultdb, 'permissions_authentication', ('id', 'client_certificate', 'ldap_server', 'ldap_use_global_catalog', 'ldap_permit_no_tls', 'ldap_bind_username', 'ldap_bind_password', 'ldap_base_dn', 'ldap_user_search_dn', 'ldap_user_filter', 'ldap_user_search_filter', 'ldap_user_group_attributes', 'ldap_group_search_dn', 'ldap_group_filter', 'ldap_group_membership_filter', 'api_oauth2_allow_all_perms', 'api_oauth2_disable_basic', 'api_oauth2_expiration', 'oidc_auth_method', 'oidc_authorize_url', 'oidc_client_id', 'oidc_client_secret', 'oidc_groups_field', 'oidc_metadata', 'oidc_metadata_url', 'oidc_private_key', 'oidc_required_key', 'oidc_required_value', 'oidc_scope', 'oidc_token_endpoint_url', 'oidc_username_field', 'source'), 'id')
        self.permissions_authentication_group_table = self._build_dict(self.defaultdb, 'auth_group', ('id', 'name'), 'id')
        self.authentication_group_permission_table = self._build_dict_join(self.defaultdb, 'auth_group_permissions', 'group_id', 'permission_id', 'auth_permission', 'name')
        if self.version['version-id'] >= '35':
            self.authentication_role_mapping_table = self._build_dict(self.defaultdb, 'permissions_rolemapping', ('id', 'name', 'value', 'source'), 'id')
            self.authentication_role_mapping_permission_table = self._build_dict_join(self.defaultdb, 'permissions_rolemapping_roles', 'rolemapping_id', 'role_id', 'auth_group', 'name')
        else:
            self.authentication_role_mapping_table = self._build_dict(self.defaultdb, 'permissions_ldaprole', ('id', 'ldap_group_dn', 'name'), 'id')
            self.authentication_role_mapping_permission_table = self._build_dict_join(self.defaultdb, 'permissions_ldaprole_roles', 'ldaprole_id', 'role_id', 'auth_group', 'name')
        if self.version['version-id'] == '34':
            self.permissions_oauth2client_table = self._build_dict(self.defaultdb, 'permissions_oauth2client', ('id', 'client_id', 'client_name', 'public_key_jwt', 'role_id'), 'id')
            self.permissions_oauth2token_table = self._build_dict_join(self.defaultdb, 'permissions_oauth2client', 'id', 'role_id', 'permissions_ldaprole', 'name')
        if self.version['version-id'] >= '35':
            self.permissions_oauth2client_table = self._build_dict(self.defaultdb, 'permissions_oauth2client', ('id', 'client_id', 'client_name', 'public_key_jwt', 'role_id'), 'id')
            self.permissions_oauth2token_table = self._build_dict_join(self.defaultdb, 'permissions_oauth2client', 'id', 'role_id', 'permissions_rolemapping', 'name')
        if self.version['version-id'] >= '34':
            self.permissions_oauth2tokens_table = self._build_dict(self.defaultdb, 'permissions_oauth2token', ('id', 'token_type', 'access_token', 'scope', 'issued_at', 'expires_at', 'client_id'), 'id')


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
        cur.execute(f"select * from {table}")
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
        cur.execute(f"select {join_table}.{join_index} as {join_index}, {table}.{field} as {field} from {join_table} left join {table} on {join_table}.{join_field} == {table}.id")
        for row in cur:
            if row[join_index] in resp:
                resp[row[join_index]].append(row[field])
            else:
                resp[row[join_index]] = [row[field]]
        return resp


    def print_auth_config(self):
        """
        Print the authentication configuration.
        """
        issues = []
        auth_config = self.permissions_authentication_table[1]
        print(f"Platform Version: {self.version['version-id']} ({self.version['pseudo-version']})")
        print()
        print('Administrator Authentication Configuration')
        print(len('Administrator Authentication Configuration') * '=')
        print()
        print(f'Authentication source: {auth_config['source']}')
        print(f'Require client certificate: {str(auth_config["client_certificate"]).capitalize()}')
        print()
        if self.version['version-id'] >= '34':
            print('Management API OAuth2 settings')
            print(len('Management API OAuth2 settings') * '=')
            print()
            print(f'Access token expiration: {auth_config["api_oauth2_expiration"]} seconds')
            print(f'Disable basic authentication: {str(auth_config["api_oauth2_disable_basic"]).replace("0", "No").replace("1", "Yes")}')
            print(f'Allow all permissions: {str(auth_config["api_oauth2_allow_all_perms"]).replace("0", "No").replace("1", "Yes")}')
            print()
        if 'LDAP' in auth_config['source']:
            print('LDAP configuration')
            print(len('LDAP configuration') * '=')
            print()
            print(f'LDAP server: {auth_config["ldap_server"]}')
            print(f'LDAP bind username: {auth_config["ldap_bind_username"]}')
            print(f'LDAP bind password: {auth_config["ldap_bind_password"][:20]}......')
            print(f'LDAP base DN: {auth_config["ldap_base_dn"]}')
            print(f'Allow insecure transport (no TLS): {str(auth_config["ldap_permit_no_tls"]).replace("0", "No").replace("1", "Yes")}')
            if not auth_config["ldap_base_dn"]:
                issues.append('No LDAP base DN configured')
            print()
            print('Advanced LDAP configuration')
            print(len('Advanced LDAP configuration') * '=')
            print()
            print(f'Search global catalog: {str(auth_config["ldap_use_global_catalog"]).replace("0", "No").replace("1", "Yes")}')
            print(f'LDAP user search DN: {auth_config["ldap_user_search_dn"]}')
            if not auth_config["ldap_user_search_dn"]:
                issues.append('No LDAP user search DN configured')
            else:
                if auth_config["ldap_base_dn"] in auth_config["ldap_user_search_dn"]:
                    issues.append('LDAP base DN is included in the user search DN')
            print(f'LDAP user filter: {auth_config["ldap_user_filter"]}')
            print(f'LDAP user search filter: {auth_config["ldap_user_search_filter"]}')
            print(f'LDAP user group attributes: {auth_config["ldap_user_group_attributes"]}')
            print(f'LDAP group search DN: {auth_config["ldap_group_search_dn"]}')
            if not auth_config["ldap_group_search_dn"]:
                issues.append('No LDAP group search DN configured')
            else:
                if auth_config["ldap_base_dn"] in auth_config["ldap_group_search_dn"]:
                    issues.append('LDAP base DN is included in the group search DN')
            print(f'LDAP group filter: {auth_config["ldap_group_filter"]}')
            print(f'LDAP group membership filter: {auth_config["ldap_group_membership_filter"]}')
            print()
        if self.version['version-id'] >= '35' and 'OIDC' in auth_config['source']:
            if auth_config["oidc_metadata"]:
                metadata = json.loads(auth_config["oidc_metadata"])
            else:
                metadata = None
            print('OpenID Connect configuration')
            print(len('OpenID Connect configuration') * '=')
            print()
            print(f'Metadata URL: {auth_config["oidc_metadata_url"]}')
            print(f'Authorize URL: {auth_config["oidc_authorize_url"]}')
            print(f'Token endpoint URL: {auth_config["oidc_token_endpoint_url"]}')
            print(f'Client ID: {auth_config["oidc_client_id"]}')
            print(f'Authentication method: {auth_config["oidc_auth_method"]}')
            print(f'Scope: {auth_config["oidc_scope"]}')
            print(f'Username field: {auth_config["oidc_username_field"]}')
            print(f'Groups field: {auth_config["oidc_groups_field"]}')
            if auth_config["oidc_required_key"]:
                print(f'Required key: {auth_config["oidc_required_key"]}')
            if auth_config["oidc_required_value"]:
                print(f'Required value: {auth_config["oidc_required_value"]}')
            print()
            if metadata:
                print('OpenID Connect metadata')
                print(len('OpenID Connect metadata') * '=')
                print()
                print(f'Token endpoint: {metadata['token_endpoint']}')
                print(f'Token endpoint auth methods supported: {metadata['token_endpoint_auth_methods_supported']}')
                print(f'JWKS URI: {metadata['jwks_uri']}')
                print(f'Response modes supported: {metadata['response_modes_supported']}')
                print(f'Subject types supported: {metadata['subject_types_supported']}')
                print(f'ID token signing alg values supported: {metadata['id_token_signing_alg_values_supported']}')
                print(f'Response types supported: {metadata['response_types_supported']}')
                print(f'Supported scopes: {metadata['scopes_supported']}')
                print(f'Issuer: {metadata['issuer']}')
                print(f'Request URI parameter supported: {metadata['request_uri_parameter_supported']}')
                print(f'User info endpoint: {metadata['userinfo_endpoint']}')
                print(f'Authorization endpoint: {metadata['authorization_endpoint']}')
                print(f'Device authorization endpoint: {metadata['device_authorization_endpoint']}')
                print(f'HTTP logout supported: {metadata['http_logout_supported']}')
                print(f'Front channel logout supported: {metadata['frontchannel_logout_supported']}')
                print(f'End session endpoint: {metadata['end_session_endpoint']}')
                print(f'Claims supported: {metadata['claims_supported']}')
                print(f'Kerberos endpoint: {metadata['kerberos_endpoint']}')
                print(f'Tenant region scope: {metadata['tenant_region_scope']}')
                print(f'Cloud instance name: {metadata['cloud_instance_name']}')
                print(f'Cloud graph hostname: {metadata['cloud_graph_host_name']}')
                print(f'Microsoft Graph URI: {metadata['msgraph_host']}')
                print(f'RBAC URL: {metadata['rbac_url']}')
                print()
        if 'LDAP' in auth_config['source'] or 'OIDC' in auth_config['source']:
            role_mapping = self.authentication_role_mapping_table
            role_mapping_permissions = self.authentication_role_mapping_permission_table
            print('Role Mappings')
            print(len('Role Mappings') * '=')
            print()
            for idx, item in enumerate(role_mapping.values(), start=1):
                if self.version['version-id'] >= '35':
                    print(f'#{idx} Name: {item["name"]}, Source: {item["source"]} ({item["value"]})')
                else:
                    print(f'#{idx} LDAP group DN: {item["ldap_group_dn"]}, Name: {item["name"]}')
                if role_mapping_permissions.keys():
                    permissions = ''
                    for permission in role_mapping_permissions[item['id']]:
                        permissions += f"{permission}, "
                    print(f"    Administrator roles: {permissions[:-1].removesuffix(',')}")
                    print()
        if self.version['version-id'] == '34':
            if self.permissions_oauth2client_table:
                print('OAuth2 Client Configuration')
                print(len('OAuth2 Client Configuration') * '=')
                print()
                for idx, item in enumerate(self.permissions_oauth2client_table.values(), start=1):
                    print(f'OAuth2 client #{idx}: {item["client_name"]}')
                    print(f'    Client ID: {item["client_id"]}')
                    print(f"    Administrator role: {self.permissions_oauth2token_table[item['id']][0]}")
                    print(f"    LDAP group dn: {self.authentication_role_mapping_table[[item['role_id']][0]]['ldap_group_dn']}")
                    print()
        if self.version['version-id'] >= '35':
            if self.permissions_oauth2client_table:
                print('OAuth2 Client Configuration')
                print(len('OAuth2 Client Configuration') * '=')
                print()
                for idx, item in enumerate(self.permissions_oauth2client_table.values(), start=1):
                    print(f'OAuth2 client #{idx}: {item["client_name"]}')
                    print(f'    Client ID: {item["client_id"]}')
                    print(f"    Administrator role: {self.permissions_oauth2token_table[item['id']][0]}")
                    print(f"    Role mapping: {self.authentication_role_mapping_table[[item['role_id']][0]]['value']}")
                    print()
        if self.version['version-id'] >= '34':
            if self.permissions_oauth2tokens_table:
                print('OAuth2 Tokens')
                print(len('OAuth2 Tokens') * '=')
                print()
                for idx, item in enumerate(self.permissions_oauth2tokens_table.values(), start=1):
                    print(f'OAuth2 token #{idx}: {self.permissions_oauth2client_table[item["client_id"]]['client_name']} (ID: {self.permissions_oauth2client_table[item["client_id"]]['client_id']})')
                    print(f'    Token type: {item["token_type"]}')
                    print(f'    Scope: {item["scope"]}')
                    print(f'    Issued at: {item["issued_at"]}')
                    print(f'    Expires at: {item["expires_at"]}')
                    print(f'    Access token: {item["access_token"]}')
                    print()
        role_config = self.permissions_authentication_group_table
        print('Administrator Role Configuration')
        print(len('Administrator Role Configuration') * '=')
        print()
        for idx, item in enumerate(role_config.values(), start=1):
            permissions = ''
            print(f'Administrator role #{idx}: {item['name']}')
            if self.authentication_group_permission_table.keys():
                for permission in self.authentication_group_permission_table[item['id']]:
                    permissions += f"{permission}, "
            print(f"    Permissions ({len(permissions[:-1].removesuffix(',').split(','))}): {permissions[:-1].removesuffix(',')}")
            print()
        if issues:
            print("Potential Issues")
            print(len("Potential Issues") * '=')
            print()
            for issue in issues:
                print(issue)
        self.defaultdb.close()


def main():
    """Main processing"""
    parser = argparse.ArgumentParser(description='Output the authentication configuration of the management node')
    parser.add_argument('snapshot', help='Snapshot folder')
    args = parser.parse_args()

    process_snapshot = PexAuth(args.snapshot)
    process_snapshot.print_auth_config()


if __name__ == "__main__":
    main()
