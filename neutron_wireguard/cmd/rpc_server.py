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

"""wireguard RPC Server.

This standalone service handles RPC callbacks from agents,
such as status updates when interfaces are configured.

This service should be started using neutron-wireguard-rpc command.
"""

import sys

from neutron.common import config as common_config
from neutron.conf import common as core_config
from neutron_lib import rpc as n_rpc
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import service

from neutron_wireguard.common import topics
from neutron_wireguard.db.wireguard import db as wg_db
from neutron_wireguard.rpc import server as rpc_server

LOG = logging.getLogger(__name__)


class WireguardRpcService(service.Service):
    """Service to handle RPC callbacks from agents."""

    def __init__(self):
        super().__init__()
        self.db = wg_db.WireguardPluginDb()

    def start(self):
        super().start()
        LOG.info("Starting wireguard RPC server")

        self.conn = n_rpc.Connection()
        endpoints = [rpc_server.WireguardServerRpcCallback(self.db)]
        self.conn.create_consumer(topics.WIREGUARD_PLUGIN_TOPIC,
                                  endpoints, fanout=False)
        self.conn.consume_in_threads()

        LOG.info("wireguard RPC server started, listening on topic: %s",
                 topics.WIREGUARD_PLUGIN_TOPIC)

    def stop(self):
        LOG.info("Stopping wireguard RPC server")
        if self.conn:
            self.conn.close()
        super().stop()


def main():
    """Main entry point for neutron-wireguard-rpc-server."""
    logging.register_options(cfg.CONF)
    oslo_messaging.set_transport_defaults(control_exchange='neutron')
    core_config.register_core_common_config_opts()
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    n_rpc.init(cfg.CONF)
    LOG.info("RPC initialized with control_exchange: neutron")
    server = WireguardRpcService()
    launcher = service.launch(cfg.CONF, server, restart_method='mutate')
    launcher.wait()


if __name__ == '__main__':
    main()
