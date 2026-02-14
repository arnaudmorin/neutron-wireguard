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

from concurrent import futures
import os
import threading

from neutron.agent.linux import ip_lib
from neutron_lib.agent import l3_extension
from neutron_lib import constants as lib_constants
from neutron_lib import context as n_context
from neutron_lib import rpc as n_rpc
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import loopingcall

from neutron_wireguard.common import topics
from neutron_wireguard.conf.wireguard import register_wireguard_opts
from neutron_wireguard.rpc import agent as rpc_agent


LOG = logging.getLogger(__name__)

WIREGUARD_CONF_TEMPLATE = """[Interface]
PrivateKey = {private_key}
ListenPort = {port}

[Peer]
PublicKey = {peer_public_key}
AllowedIPs = {peer_allowed_ips}
{peer_extra}"""


class WireguardLockManager:
    """Manages per-wireguard locks to prevent concurrent operations.

    This ensures that only one operation (create, update, delete, sync)
    can be performed on a specific wireguard at a time.
    """

    def __init__(self):
        self._locks = {}
        self._master_lock = threading.Lock()

    def get_lock(self, wireguard_id):
        """Get or create a lock for a specific wireguard.

        Returns:
            threading.Lock for the specified wireguard_id
        """
        with self._master_lock:
            if wireguard_id not in self._locks:
                self._locks[wireguard_id] = threading.Lock()
            return self._locks[wireguard_id]

    def remove_lock(self, wireguard_id):
        """Remove a lock for a deleted wireguard."""
        with self._master_lock:
            self._locks.pop(wireguard_id, None)


class WireguardAgent(l3_extension.L3AgentExtension):
    """wireguard agent support to be used by Neutron L3 agent."""

    def __init__(self, host, conf):
        LOG.debug("Initializing wireguard agent")
        self.agent_api = None
        self.conf = conf
        self.host = host
        self.server_rpc = rpc_agent.WireguardServerRpcApi()
        self._lock_manager = WireguardLockManager()

    def initialize(self, connection, driver_type):
        LOG.debug("Initializing wireguard agent extension")
        self._register_rpc_consumers()
        self._sync_wireguards_from_server()
        self._start_periodic_sync()

    def consume_api(self, agent_api):
        LOG.debug("Loading consume_api for wireguard")
        self.agent_api = agent_api

    def _start_periodic_sync(self):
        """Start a periodic task to sync wireguard configurations."""
        interval = self.conf.wireguard.periodic_sync_interval
        if not interval:
            LOG.info("Periodic wireguard sync is disabled")
            return
        LOG.info("Starting periodic wireguard sync every %d seconds",
                 interval)
        self._periodic_sync_loop = loopingcall.FixedIntervalLoopingCall(
            self._sync_wireguards_from_server)
        self._periodic_sync_loop.start(interval=interval)

    def _sync_wireguards_from_server(self):
        """Sync wireguard configurations from the server on startup.

        Fetches all wireguards that should be configured on this host
        and ensures they are properly set up using parallel execution.
        """
        LOG.info("Syncing wireguard configurations from server for host %s",
                 self.host)
        context = n_context.get_admin_context()
        try:
            wireguards = self.server_rpc.get_wireguards_for_host(
                context, self.host)
            LOG.info("Received %d wireguards to sync", len(wireguards))

            if not wireguards:
                return

            def sync_one(wg):
                try:
                    self._sync_wireguard(context, wg)
                    return wg['id'], None
                except Exception as e:
                    LOG.error("Failed to sync wireguard %s: %s", wg['id'], e)
                    return wg['id'], e

            with futures.ThreadPoolExecutor(
                    max_workers=self.conf.wireguard.sync_max_workers
                    ) as executor:
                results = list(executor.map(sync_one, wireguards))

            failed = [wg_id for wg_id, error in results if error is not None]
            if failed:
                LOG.warning("Failed to sync %d wireguards: %s",
                            len(failed), failed)
        except Exception as e:
            LOG.error("Failed to fetch wireguards from server: %s", e)

    def _sync_wireguard(self, context, wireguard):
        """Sync a single wireguard configuration.

        Creates or updates the wireguard interface as needed.
        """
        router_id = wireguard['router_id']
        wireguard_id = wireguard['id']
        namespace = self._get_snat_namespace(router_id)
        if_name = self._get_interface_name(wireguard_id)

        LOG.info("Syncing wireguard %s (interface %s) in namespace %s",
                 wireguard_id, if_name, namespace)

        # Use update_wireguard which handles both create and update cases
        self.update_wireguard(context, wireguard)

    def _register_rpc_consumers(self):
        self.conn = n_rpc.Connection()
        endpoints = [rpc_agent.WireguardAgentRpcCallback(self)]
        self.conn.create_consumer(
            topics.WIREGUARD_AGENT_TOPIC, endpoints, fanout=False)
        self.conn.consume_in_threads()

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

    def _build_allowed_ips(self, wireguard):
        """Build the AllowedIPs list including the wireguard's own IP.

        Combines the configured peer_allowed_ips with the wireguard's
        ipaddress to ensure traffic to the local interface is allowed.
        """
        allowed_ips = list(wireguard.get('peer_allowed_ips', []))

        ipaddress = wireguard.get('ipaddress')
        if ipaddress:
            # Add the wireguard's own IP to allowed IPs
            # If it's already a CIDR, use as-is; otherwise add /32
            if '/' not in ipaddress:
                ipaddress = ipaddress + '/32'
            if ipaddress not in allowed_ips:
                allowed_ips.append(ipaddress)

        return allowed_ips

    def _write_wireguard_conf(self, wireguard):
        """Write the wireguard configuration file."""
        router_id = wireguard['router_id']
        wireguard_id = wireguard['id']
        conf_path = self._get_wireguard_conf_path(router_id, wireguard_id)

        conf_dir = os.path.dirname(conf_path)
        if not os.path.exists(conf_dir):
            os.makedirs(conf_dir, mode=0o755)

        allowed_ips = self._build_allowed_ips(wireguard)
        peer_allowed_ips = ', '.join(allowed_ips)

        peer_extra_lines = []
        peer_endpoint = wireguard.get('peer_endpoint')
        if peer_endpoint:
            peer_extra_lines.append('Endpoint = %s' % peer_endpoint)
            peer_extra_lines.append('PersistentKeepalive = 25')

        conf_content = WIREGUARD_CONF_TEMPLATE.format(
            private_key=wireguard.get('private_key', ''),
            port=wireguard.get('port', 51820),
            peer_public_key=wireguard.get('peer_public_key', ''),
            peer_allowed_ips=peer_allowed_ips,
            peer_extra='\n'.join(peer_extra_lines) + '\n',
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

    def _get_wireguard_interfaces(self, namespace):
        """List wireguard interfaces (wg-*) in a namespace."""
        try:
            output = self._execute(namespace,
                                   ['ip', '-o', 'link', 'show', 'type',
                                    'wireguard'])
        except Exception:
            return []
        if_names = []
        if output:
            for line in output.strip().split('\n'):
                if line:
                    # Format: "N: if_name@...: ..."
                    if_names.append(line.split(':')[1].strip().split('@')[0])
        return if_names

    def _get_router_iptables_manager(self, router_id):
        """Get the iptables manager for a router's namespace.

        Returns the snat_iptables_manager for DVR routers, falling back
        to the regular iptables_manager for legacy routers.
        Returns (router_info, iptables_manager) or (None, None).
        """
        if not self.agent_api:
            return None, None
        ri = self.agent_api.get_router_info(router_id)
        if not ri:
            return None, None
        ipt_mgr = getattr(ri, 'snat_iptables_manager', None)
        if not ipt_mgr:
            ipt_mgr = ri.iptables_manager
        return ri, ipt_mgr

    def _restore_address_scope_marks(self, router_id):
        """Re-add address scope marks for all wireguard interfaces on a router.

        Called from the update_router / add_router hooks after the L3 agent
        has processed the router and potentially rebuilt the scope chain.
        """
        ri, ipt_mgr = self._get_router_iptables_manager(router_id)
        if not ipt_mgr:
            return
        namespace = self._get_snat_namespace(router_id)
        if_names = self._get_wireguard_interfaces(namespace)
        if not if_names:
            return
        mark = ri.get_address_scope_mark_mask()
        existing_rules = {r.rule for r in ipt_mgr.ipv4['mangle'].rules
                          if r.chain == 'scope'}
        new_rules = []
        for if_name in if_names:
            rule = ri.address_scope_mangle_rule(if_name, mark)
            if rule not in existing_rules:
                new_rules.append(rule)
        if not new_rules:
            return
        with ipt_mgr.defer_apply():
            for rule in new_rules:
                ipt_mgr.ipv4['mangle'].add_rule('scope', rule)
        LOG.debug("Restored address scope marks for %d wireguard "
                  "interfaces on router %s", len(new_rules), router_id)

    def _sync_routes_for_allowed_ips(self, namespace, if_name, allowed_ips):
        """Sync routes to match the current allowed IPs.

        Removes stale routes and adds missing ones.
        """
        # Get current routes for this interface
        list_cmd = ['ip', 'route', 'show', 'dev', if_name]
        try:
            output = self._execute(namespace, list_cmd)
            current_routes = set()
            if output:
                for line in output.strip().split('\n'):
                    if line:
                        # First word is the destination
                        current_routes.add(line.split()[0])
        except Exception:
            current_routes = set()

        desired_routes = set(allowed_ips)

        # Remove stale routes
        for cidr in current_routes - desired_routes:
            remove_cmd = ['ip', 'route', 'del', cidr, 'dev', if_name]
            self._execute(namespace, remove_cmd, check_exit_code=False)
            LOG.info("Removed stale route for %s via %s", cidr, if_name)

        # Add missing routes
        for cidr in desired_routes - current_routes:
            add_cmd = ['ip', 'route', 'add', cidr, 'dev', if_name]
            try:
                self._execute(namespace, add_cmd)
                LOG.info("Added route for %s via interface %s", cidr, if_name)
            except Exception as e:
                LOG.warning("Failed to add route for %s via %s: %s",
                            cidr, if_name, e)

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
        self._configure_wireguard(context, wireguard)

    def update_wireguard(self, context, wireguard):
        """Update wireguard configuration on an existing interface.

        If the interface doesn't exist (e.g., after agent restart),
        it will be created before applying the configuration.
        """
        self._configure_wireguard(context, wireguard)

    def _configure_wireguard(self, context, wireguard):
        """Configure a wireguard interface (create or update).

        This method is idempotent - it will create the interface if it
        doesn't exist, or update it if it does. All operations (interface
        creation, address assignment, routes, iptables rules) are designed
        to be safely re-applied.
        """
        wireguard_id = wireguard['id']
        lock = self._lock_manager.get_lock(wireguard_id)

        with lock:
            LOG.debug("Acquired lock for wireguard %s", wireguard_id)
            self._do_configure_wireguard(context, wireguard)

    def _do_configure_wireguard(self, context, wireguard):
        """Internal method to configure wireguard (must hold lock)."""
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
            # Ensure address scope mark rule exists
            self._restore_address_scope_marks(router_id)
            # Sync routes for peer allowed IPs (add missing, remove stale)
            allowed_ips = wireguard.get('peer_allowed_ips', [])
            self._sync_routes_for_allowed_ips(namespace, if_name, allowed_ips)
        except Exception as e:
            LOG.error("Failed to configure wireguard %s: %s", wireguard_id, e)
            self.server_rpc.update_wireguard_agent_status(
                context, wireguard_id, lib_constants.ERROR, self.host)
            return

        self.server_rpc.update_wireguard_agent_status(
            context, wireguard_id, lib_constants.ACTIVE, self.host)
        LOG.info("wireguard %s configured and ACTIVE", wireguard_id)

    def delete_wireguard(self, context, wireguard_id, router_id):
        """Delete wireguard interface and configuration."""
        lock = self._lock_manager.get_lock(wireguard_id)

        with lock:
            LOG.debug("Acquired lock for wireguard %s (delete)", wireguard_id)
            self._do_delete_wireguard(context, wireguard_id, router_id)

        # Clean up the lock after deletion
        self._lock_manager.remove_lock(wireguard_id)

    def _do_delete_wireguard(self, context, wireguard_id, router_id):
        """Internal method to delete wireguard (must hold lock)."""
        namespace = self._get_snat_namespace(router_id)
        if_name = self._get_interface_name(wireguard_id)

        self._remove_address_scope_mark(router_id, if_name)
        self._destroy_wg_interface(namespace, if_name)
        self._remove_wireguard_conf(router_id, wireguard_id)

    def _remove_address_scope_mark(self, router_id, if_name):
        """Remove address scope mark rule for a wireguard interface."""
        ri, ipt_mgr = self._get_router_iptables_manager(router_id)
        if not ipt_mgr:
            return
        mark = ri.get_address_scope_mark_mask()
        rule = ri.address_scope_mangle_rule(if_name, mark)
        with ipt_mgr.defer_apply():
            ipt_mgr.ipv4['mangle'].remove_rule('scope', rule)

    def add_router(self, context, data):
        # data['id'] is router_id
        self._restore_address_scope_marks(data['id'])

    def update_router(self, context, data):
        # data['id'] is router_id
        self._restore_address_scope_marks(data['id'])

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
        register_wireguard_opts(self.conf)
        super().__init__(host=self.conf.host, conf=self.conf)
