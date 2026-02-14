# Copyright 2026 OVHcloud
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""wireguard API extension definition."""

import abc
import types

from neutron_lib.api import converters
from neutron_lib.api import extensions as api_extensions
from neutron_lib.db import constants as db_const
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.services import base as service_base

from neutron.api.v2 import resource_helper


# API Definition
ALIAS = 'wireguard'
IS_SHIM_EXTENSION = False
IS_STANDARD_ATTR_EXTENSION = False
NAME = 'wireguard'
DESCRIPTION = 'wireguard extension for Neutron'
UPDATED_TIMESTAMP = '2026-01-01T00:00:00-00:00'
API_PREFIX = ''
REQUIRED_EXTENSIONS = []
OPTIONAL_EXTENSIONS = []
SUB_RESOURCE_ATTRIBUTE_MAP = {}
ACTION_MAP = {}
ACTION_STATUS = {}

RESOURCE_ATTRIBUTE_MAP = {
    'wireguards': {
        'id': {
            'allow_post': False,
            'allow_put': False,
            'validate': {'type:uuid': None},
            'is_visible': True,
            'is_filter': True,
            'is_sort_key': True,
            'primary_key': True,
        },
        'project_id': {
            'allow_post': True,
            'allow_put': False,
            'validate': {'type:string': db_const.PROJECT_ID_FIELD_SIZE},
            'required_by_policy': True,
            'is_visible': True,
            'is_filter': True,
            'is_sort_key': True,
        },
        'name': {
            'allow_post': True,
            'allow_put': True,
            'validate': {'type:string': db_const.NAME_FIELD_SIZE},
            'default': '',
            'is_visible': True,
            'is_filter': True,
            'is_sort_key': True,
        },
        'private_key': {
            'allow_post': False,
            'allow_put': False,
            'is_visible': False,
        },
        'public_key': {
            'allow_post': False,
            'allow_put': False,
            'is_visible': True,
        },
        'port': {
            'allow_post': True,
            'allow_put': True,
            'validate': {'type:range': [1, 65535]},
            'convert_to': converters.convert_to_int,
            'default': 51820,
            'is_visible': True,
            'is_filter': True,
        },
        'ipaddress': {
            'allow_post': True,
            'allow_put': True,
            'validate': {'type:subnet': None},
            'is_visible': True,
        },
        'peer_public_key': {
            'allow_post': True,
            'allow_put': True,
            'validate': {'type:string_or_none': 44},
            'is_visible': True,
            'default': None,
        },
        'peer_allowed_ips': {
            'allow_post': True,
            'allow_put': True,
            'validate': {'type:list_of_subnets_or_none': None},
            'default': [],
            'is_visible': True,
        },
        'peer_endpoint': {
            'allow_post': True,
            'allow_put': True,
            'validate': {'type:string_or_none': 255},
            'default': None,
            'is_visible': True,
            'is_filter': True,
        },
        'router_id': {
            'allow_post': True,
            'allow_put': False,
            'validate': {'type:uuid': None},
            'is_visible': True,
            'is_filter': True,
        },
        'status': {
            'allow_post': False,
            'allow_put': False,
            'is_visible': True,
            'is_filter': True,
        },
        'agent_statuses': {
            'allow_post': False,
            'allow_put': False,
            'is_visible': True,
        },
    },
}


def _create_api_definition():
    """Create an api_definition module-like object with all required attributes."""
    api_def = types.ModuleType('wireguard_api_definition')
    api_def.ALIAS = ALIAS
    api_def.IS_SHIM_EXTENSION = IS_SHIM_EXTENSION
    api_def.IS_STANDARD_ATTR_EXTENSION = IS_STANDARD_ATTR_EXTENSION
    api_def.NAME = NAME
    api_def.DESCRIPTION = DESCRIPTION
    api_def.UPDATED_TIMESTAMP = UPDATED_TIMESTAMP
    api_def.API_PREFIX = API_PREFIX
    api_def.REQUIRED_EXTENSIONS = REQUIRED_EXTENSIONS
    api_def.OPTIONAL_EXTENSIONS = OPTIONAL_EXTENSIONS
    api_def.SUB_RESOURCE_ATTRIBUTE_MAP = SUB_RESOURCE_ATTRIBUTE_MAP
    api_def.ACTION_MAP = ACTION_MAP
    api_def.ACTION_STATUS = ACTION_STATUS
    api_def.RESOURCE_ATTRIBUTE_MAP = RESOURCE_ATTRIBUTE_MAP
    return api_def


class Wireguard(api_extensions.APIExtensionDescriptor):
    """wireguard extension."""

    api_definition = _create_api_definition()

    @classmethod
    def get_resources(cls):
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        return resource_helper.build_resource_info(
            plural_mappings,
            RESOURCE_ATTRIBUTE_MAP,
            plugin_constants.VPN,
            register_quota=True,
            translate_name=True)

    @classmethod
    def get_plugin_interface(cls):
        return WireguardPluginBase


class WireguardPluginBase(service_base.ServicePluginBase, metaclass=abc.ABCMeta):
    """Base class for wireguard plugin."""

    path_prefix = API_PREFIX

    def get_plugin_type(self):
        return plugin_constants.VPN

    def get_plugin_description(self):
        return 'wireguard service plugin'

    @abc.abstractmethod
    def create_wireguard(self, context, wireguard):
        """Create a wireguard."""
        pass

    @abc.abstractmethod
    def update_wireguard(self, context, wireguard_id, wireguard):
        """Update a wireguard."""
        pass

    @abc.abstractmethod
    def delete_wireguard(self, context, wireguard_id):
        """Delete a wireguard."""
        pass

    @abc.abstractmethod
    def get_wireguard(self, context, wireguard_id, fields=None):
        """Get a wireguard."""
        pass

    @abc.abstractmethod
    def get_wireguards(self, context, filters=None, fields=None):
        """List wireguards."""
        pass
