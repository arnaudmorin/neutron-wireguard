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

"""Agent-side RPC for wireguard.

This module contains:
- WireguardServerRpcApi: Client to send updates to the server
- WireguardAgentRpcCallback: Handler for RPC calls from server
"""

from neutron_lib import rpc as n_rpc
from oslo_log import log as logging
import oslo_messaging

from neutron_wireguard.common import topics

LOG = logging.getLogger(__name__)


class WireguardServerRpcApi:
    """RPC client for agent to communicate with the server."""

    def __init__(self):
        target = oslo_messaging.Target(topic=topics.WIREGUARD_PLUGIN_TOPIC,
                                       version='1.0')
        self.client = n_rpc.get_client(target)

    def update_wireguard_agent_status(self, context, wireguard_id, status, host):
        """Report wireguard status to the server."""
        cctxt = self.client.prepare()
        LOG.debug("Sending status update for wireguard %s: %s (host=%s)",
                 wireguard_id, status, host)
        cctxt.cast(context, 'update_wireguard_agent_status',
                   wireguard_id=wireguard_id, status=status, host=host)

    def get_wireguards_for_host(self, context, host):
        """Request all wireguards that should be configured on this host.

        This is used by the agent to sync configurations on startup.
        Returns a list of wireguard dictionaries with complete configuration.
        """
        cctxt = self.client.prepare()
        LOG.debug("Requesting wireguard sync for host %s", host)
        return cctxt.call(context, 'get_wireguards_for_host', host=host)


class WireguardAgentRpcCallback:
    """RPC callback handler for calls from server."""

    target = oslo_messaging.Target(version='1.0')

    def __init__(self, agent):
        self.agent = agent

    def wireguard_created(self, context, wireguard):
        """Handle wireguard created notification."""
        self.agent.create_wireguard(context, wireguard)

    def wireguard_updated(self, context, wireguard):
        """Handle wireguard updated notification."""
        self.agent.update_wireguard(context, wireguard)

    def wireguard_deleted(self, context, wireguard_id, router_id):
        """Handle wireguard deleted notification."""
        self.agent.delete_wireguard(context, wireguard_id, router_id)
