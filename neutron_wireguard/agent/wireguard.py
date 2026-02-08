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

import os

from neutron.agent.linux import ip_lib
from neutron_lib.agent import l3_extension
from neutron_lib import constants as lib_constants
from neutron_lib import rpc as n_rpc
from oslo_config import cfg
from oslo_log import log as logging

from neutron_wireguard.common import topics
from neutron_wireguard.rpc import agent as rpc_agent

LOG = logging.getLogger(__name__)

WIREGUARD_CONF_TEMPLATE = """[Interface]
PrivateKey = {private_key}
ListenPort = {port}

[Peer]
PublicKey = {peer_public_key}
AllowedIPs = {peer_allowed_ips}
Endpoint = {peer_endpoint}
PersistentKeepalive = 25
"""


class WireguardAgent(l3_extension.L3AgentExtension):
    """wireguard agent support to be used by Neutron L3 agent."""

    def initialize(self, connection, driver_type):
        LOG.debug("Initializing wireguard agent extension")
        self._register_rpc_consumers()

    def _register_rpc_consumers(self):
        self.conn = n_rpc.Connection()
        endpoints = [rpc_agent.WireguardAgentRpcCallback(self)]
        self.conn.create_consumer(
            topics.WIREGUARD_AGENT_TOPIC, endpoints, fanout=False)
        self.conn.consume_in_threads()

    def consume_api(self, agent_api):
        LOG.debug("Loading consume_api for wireguard")
        self.agent_api = agent_api

    def __init__(self, host, conf):
        LOG.debug("Initializing wireguard agent")
        self.agent_api = None
        self.conf = conf
        self.host = host
        self.server_rpc = rpc_agent.WireguardServerRpcApi()

    def _get_snat_namespace(self, router_id):
        """Get the SNAT namespace name for a router."""
        return "snat-%s" % router_id

    def _get_interface_name(self, wireguard_id):
        """Get the wireguard interface name (max 15 chars)."""
        return "wg-%s" % wireguard_id[:11]

    def _get_wireguard_conf_path(self, router_id, wireguard_id):
        """Get the path to the wireguard config file."""
        conf_dir = os.path.join(self.conf.state_path,
                                "wireguard", router_id)
        return os.path.join(conf_dir, "%s.conf" %
                            self._get_interface_name(wireguard_id))

    def _execute(self, namespace, cmd, check_exit_code=True,
                 extra_ok_codes=None):
        """Execute a command inside the given network namespace."""
        ip_wrapper = ip_lib.IPWrapper(namespace=namespace)
        return ip_wrapper.netns.execute(cmd,
                                        check_exit_code=check_exit_code,
                                        extra_ok_codes=extra_ok_codes,
                                        privsep_exec=True)

    def _write_wireguard_conf(self, wireguard):
        """Write the wireguard configuration file."""
        router_id = wireguard['router_id']
        wireguard_id = wireguard['id']
        conf_path = self._get_wireguard_conf_path(router_id, wireguard_id)

        conf_dir = os.path.dirname(conf_path)
        if not os.path.exists(conf_dir):
            os.makedirs(conf_dir, mode=0o755)

        peer_allowed_ips = ', '.join(wireguard.get('peer_allowed_ips', []))
        conf_content = WIREGUARD_CONF_TEMPLATE.format(
            private_key=wireguard.get('private_key', ''),
            port=wireguard.get('port', 51820),
            peer_public_key=wireguard.get('peer_public_key', ''),
            peer_allowed_ips=peer_allowed_ips,
            peer_endpoint=wireguard.get('peer_endpoint', ''),
        )

        with open(conf_path, 'w') as f:
            f.write(conf_content)
        os.chmod(conf_path, 0o600)

        LOG.info("Wrote wireguard config to %s", conf_path)
        return conf_path

    def _remove_wireguard_conf(self, router_id, wireguard_id):
        """Remove the wireguard configuration file."""
        conf_path = self._get_wireguard_conf_path(router_id, wireguard_id)
        if os.path.exists(conf_path):
            os.remove(conf_path)
            LOG.info("Removed wireguard config %s", conf_path)

    def _create_wg_interface(self, namespace, if_name):
        """Create a wireguard interface inside the router namespace."""
        self._execute(namespace,
                      ['ip', 'link', 'add', if_name, 'type', 'wireguard'])
        LOG.info("Created wireguard interface %s in namespace %s",
                 if_name, namespace)

    def _configure_wg_interface(self, namespace, if_name, conf_path):
        """Apply wireguard config to the interface using wg setconf."""
        self._execute(namespace, ['wg', 'setconf', if_name, conf_path])
        LOG.info("Configured wireguard interface %s from %s",
                 if_name, conf_path)

    def _flush_interface_addresses(self, namespace, if_name):
        """Remove all IP addresses from the wireguard interface."""
        self._execute(namespace,
                      ['ip', 'addr', 'flush', 'dev', if_name],
                      check_exit_code=False)
        LOG.info("Flushed IP addresses from interface %s", if_name)

    def _set_interface_address(self, namespace, if_name, ipaddress):
        """Set the IP address on the wireguard interface."""
        if ipaddress:
            self._execute(namespace,
                          ['ip', 'addr', 'add', ipaddress, 'dev', if_name])
            LOG.info("Set IP address %s on interface %s", ipaddress, if_name)

    def _update_interface_address(self, namespace, if_name, ipaddress):
        """Update the IP address on the wireguard interface."""
        self._flush_interface_addresses(namespace, if_name)
        self._set_interface_address(namespace, if_name, ipaddress)

    def _bring_up_wg_interface(self, namespace, if_name):
        """Bring the wireguard interface up."""
        self._execute(namespace,
                      ['ip', 'link', 'set', if_name, 'up'])
        LOG.info("Brought up wireguard interface %s in namespace %s",
                 if_name, namespace)

    def _destroy_wg_interface(self, namespace, if_name):
        """Remove the wireguard interface from the namespace."""
        self._execute(namespace,
                      ['ip', 'link', 'del', if_name],
                      check_exit_code=False)
        LOG.info("Removed wireguard interface %s from namespace %s",
                 if_name, namespace)

    def _interface_exists(self, namespace, if_name):
        """Check if the wireguard interface exists in the namespace."""
        try:
            self._execute(namespace,
                          ['ip', 'link', 'show', if_name])
            return True
        except Exception:
            return False

    def _ensure_wg_interface(self, namespace, if_name):
        """Ensure the wireguard interface exists, create if missing."""
        if not self._interface_exists(namespace, if_name):
            LOG.info("Interface %s not found in namespace %s, creating it",
                     if_name, namespace)
            self._create_wg_interface(namespace, if_name)
            return True
        return False

    def create_wireguard(self, context, wireguard):
        """Create wireguard interface and apply configuration."""
        router_id = wireguard['router_id']
        wireguard_id = wireguard['id']
        namespace = self._get_snat_namespace(router_id)
        if_name = self._get_interface_name(wireguard_id)

        try:
            conf_path = self._write_wireguard_conf(wireguard)
            self._create_wg_interface(namespace, if_name)
            self._configure_wg_interface(namespace, if_name, conf_path)
            self._set_interface_address(namespace, if_name,
                                        wireguard.get('ipaddress'))
            self._bring_up_wg_interface(namespace, if_name)
            # Report success to plugin
            self.server_rpc.update_wireguard_status(
                context, wireguard_id, lib_constants.ACTIVE)
            LOG.info("wireguard %s is now ACTIVE", wireguard_id)
        except Exception as e:
            LOG.error("Failed to create wireguard %s: %s", wireguard_id, e)
            self.server_rpc.update_wireguard_status(
                context, wireguard_id, lib_constants.ERROR)

    def update_wireguard(self, context, wireguard):
        """Update wireguard configuration on an existing interface.

        If the interface doesn't exist (e.g., after agent restart),
        it will be created before applying the configuration.
        """
        router_id = wireguard['router_id']
        wireguard_id = wireguard['id']
        namespace = self._get_snat_namespace(router_id)
        if_name = self._get_interface_name(wireguard_id)

        try:
            conf_path = self._write_wireguard_conf(wireguard)
            created = self._ensure_wg_interface(namespace, if_name)
            self._configure_wg_interface(namespace, if_name, conf_path)
            self._update_interface_address(namespace, if_name,
                                           wireguard.get('ipaddress'))
            if created:
                self._bring_up_wg_interface(namespace, if_name)
            # Report success to plugin
            self.server_rpc.update_wireguard_status(
                context, wireguard_id, lib_constants.ACTIVE)
            LOG.info("wireguard %s updated and ACTIVE", wireguard_id)
        except Exception as e:
            LOG.error("Failed to update wireguard %s: %s", wireguard_id, e)
            self.server_rpc.update_wireguard_status(
                context, wireguard_id, lib_constants.ERROR)

    def delete_wireguard(self, context, wireguard_id, router_id):
        """Delete wireguard interface and configuration."""
        namespace = self._get_snat_namespace(router_id)
        if_name = self._get_interface_name(wireguard_id)

        self._destroy_wg_interface(namespace, if_name)
        self._remove_wireguard_conf(router_id, wireguard_id)

    def add_router(self, context, data):
        pass

    def update_router(self, context, data):
        pass

    def delete_router(self, context, data):
        pass

    def ha_state_change(self, context, data):
        pass

    def update_network(self, context, data):
        pass


class L3WithWireguard(WireguardAgent):

    def __init__(self, conf=None):
        if conf:
            self.conf = conf
        else:
            self.conf = cfg.CONF
        super().__init__(host=self.conf.host, conf=self.conf)
