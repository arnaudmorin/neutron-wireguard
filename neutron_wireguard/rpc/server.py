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

"""Server-side RPC for wireguard.

This module contains:
- WireguardAgentRpcApi: Client to send notifications to agents
- WireguardServerRpcCallback: Handler for RPC calls from agents
"""

from neutron_lib import rpc as n_rpc
from oslo_log import log as logging
import oslo_messaging

from neutron_wireguard.common import topics

LOG = logging.getLogger(__name__)


class WireguardAgentRpcApi:
    """RPC client for server to notify agents."""

    def __init__(self, topic=topics.WIREGUARD_AGENT_TOPIC):
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def wireguard_created(self, context, wireguard, host):
        """Notify agent about created wireguard."""
        cctxt = self.client.prepare(server=host)
        cctxt.cast(context, 'wireguard_created', wireguard=wireguard)

    def wireguard_updated(self, context, wireguard, host):
        """Notify agent about updated wireguard."""
        cctxt = self.client.prepare(server=host)
        cctxt.cast(context, 'wireguard_updated', wireguard=wireguard)

    def wireguard_deleted(self, context, wireguard_id, router_id, host):
        """Notify agent about deleted wireguard."""
        cctxt = self.client.prepare(server=host)
        cctxt.cast(context, 'wireguard_deleted',
                   wireguard_id=wireguard_id, router_id=router_id)


class WireguardServerRpcCallback:
    """RPC callback handler for calls from agents."""

    target = oslo_messaging.Target(version='1.0')

    def __init__(self, plugin):
        self.plugin = plugin

    def update_wireguard_status(self, context, wireguard_id, status):
        """Handle status update from agent."""
        LOG.info("Received status update for wireguard %s: %s",
                 wireguard_id, status)
        result = self.plugin.update_wireguard_status(context, wireguard_id,
                                                     status)
        return result

    def get_wireguards_for_host(self, context, host):
        """Return all wireguards that should be configured on the given host.

        This is called by the L3 agent extension to sync wireguard
        configurations on startup or reconnection.
        """
        LOG.info("Agent %s requesting wireguard sync", host)
        return self.plugin.get_wireguards_for_host(context, host)
