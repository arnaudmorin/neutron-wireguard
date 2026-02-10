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

import base64

from cryptography.hazmat.primitives.asymmetric import x25519
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_log import log as logging

from neutron_wireguard.db.wireguard import db as wg_db
from neutron_wireguard.rpc import server as rpc_server

LOG = logging.getLogger(__name__)


def generate_wireguard_keypair():
    """Generate a wireguard key pair using Curve25519.

    Returns:
        tuple: (private_key, public_key) as base64-encoded strings
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    # wireguard uses raw 32-byte keys, base64 encoded
    private_key_bytes = private_key.private_bytes_raw()
    public_key_bytes = public_key.public_bytes_raw()

    private_key_b64 = base64.b64encode(private_key_bytes).decode('ascii')
    public_key_b64 = base64.b64encode(public_key_bytes).decode('ascii')

    return private_key_b64, public_key_b64


class WireguardPlugin(wg_db.WireguardPluginDb):
    """Implementation of the wireguard Service Plugin.

    This class manages the workflow of wireguard request/response.
    Database operations are implemented in WireguardPluginDb.
    """

    supported_extension_aliases = ['wireguard']

    def __init__(self):
        super().__init__()
        self.agent_rpc = rpc_server.WireguardAgentRpcApi()
        self.l3_plugin = directory.get_plugin(plugin_constants.L3)
        LOG.info("wireguard plugin initialized")

    def _get_hosts_for_router(self, context, router_id):
        """Get hosts where the router is scheduled."""
        agents = self.l3_plugin.list_l3_agents_hosting_router(
            context, router_id)['agents']
        return [agent['host'] for agent in agents]

    def _notify_agent_created(self, context, wg):
        """Notify agents about wireguard creation if peer config is complete."""
        if not self._is_peer_config_complete(wg):
            LOG.info("Peer configuration incomplete, skipping agent notification")
            return
        for host in self._get_hosts_for_router(context, wg['router_id']):
            LOG.info("Notifying agent %s to configure wireguard", host)
            self.agent_rpc.wireguard_created(context, wg, host)

    def _notify_agent_updated(self, context, wg):
        """Notify agents about wireguard update if peer config is complete."""
        if not self._is_peer_config_complete(wg):
            LOG.info("Peer configuration incomplete, skipping agent notification")
            return
        for host in self._get_hosts_for_router(context, wg['router_id']):
            LOG.info("Notifying agent %s to update wireguard", host)
            self.agent_rpc.wireguard_updated(context, wg, host)

    def create_wireguard(self, context, wireguard):
        """Create a wireguard interface."""
        LOG.debug("Creating wireguard: %s", wireguard)

        # Validate router exists before proceeding
        # get_router will raise RouterNotFound if it doesn't exist
        wg_data = wireguard['wireguard']
        self.l3_plugin.get_router(context, wg_data['router_id'])

        # Generate keys server-side
        private_key, public_key = generate_wireguard_keypair()
        wg_data['private_key'] = private_key
        wg_data['public_key'] = public_key

        wg = super().create_wireguard(context, wireguard)
        self._notify_agent_created(context, wg)
        return wg

    def update_wireguard(self, context, wireguard_id, wireguard):
        """Update a wireguard interface."""
        LOG.debug("Updating wireguard %s: %s", wireguard_id, wireguard)
        wg = super().update_wireguard(context, wireguard_id, wireguard)
        self._notify_agent_updated(context, wg)
        return wg

    def delete_wireguard(self, context, wireguard_id):
        """Delete a wireguard interface."""
        LOG.debug("Deleting wireguard: %s", wireguard_id)
        wg = self.get_wireguard(context, wireguard_id)
        router_id = wg['router_id']
        super().delete_wireguard(context, wireguard_id)
        for host in self._get_hosts_for_router(context, router_id):
            self.agent_rpc.wireguard_deleted(context, wireguard_id,
                                                  router_id, host)

