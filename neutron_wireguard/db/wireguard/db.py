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

from neutron.db.models import agent as agent_model
from neutron.db.models import l3agent as l3agent_model
from neutron_lib import constants as lib_constants
from neutron_lib.db import api as db_api
from neutron_lib.db import model_query
from neutron_lib.db import utils as db_utils
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import l3 as l3_exception
from oslo_log import log as logging
from oslo_utils import uuidutils

from neutron_wireguard.db.wireguard import models
from neutron_wireguard.extensions import wireguard as wg_ext

LOG = logging.getLogger(__name__)


class WireguardNotFound(n_exc.NotFound):
    """Exception raised when a wireguard interface is not found."""
    message = "Wireguard %(wireguard_id)s could not be found."


class WireguardPluginDb(wg_ext.WireguardPluginBase):
    """wireguard plugin database class using SQLAlchemy models."""

    def _get_wireguard(self, context, wireguard_id):
        """Get a wireguard interface by ID."""
        try:
            wg = model_query.get_by_id(context, models.Wireguard, wireguard_id)
        except Exception:
            # Handle invalid UUID format (e.g., when user passes a name)
            raise WireguardNotFound(wireguard_id=wireguard_id)
        if not wg:
            raise WireguardNotFound(wireguard_id=wireguard_id)
        return wg

    def _make_wireguard_dict(self, wireguard, fields=None):
        """Convert a wireguard DB object to a dictionary."""
        res = {
            'id': wireguard['id'],
            'project_id': wireguard['project_id'],
            'name': wireguard['name'],
            'private_key': wireguard['private_key'],
            'public_key': wireguard['public_key'],
            'port': wireguard['port'],
            'ipaddress': wireguard['ipaddress'],
            'peer_public_key': wireguard['peer_public_key'],
            'peer_endpoint': wireguard['peer_endpoint'],
            'peer_allowed_ips': wireguard['peer_allowed_ips'] or [],
            'router_id': wireguard['router_id'],
            'status': wireguard['status'],
        }
        return db_utils.resource_fields(res, fields)

    def create_wireguard(self, context, wireguard):
        """Create a wireguard interface."""
        wg = wireguard['wireguard']

        with db_api.CONTEXT_WRITER.using(context):
            wg_db = models.Wireguard(
                id=uuidutils.generate_uuid(),
                project_id=wg['project_id'],
                name=wg.get('name', ''),
                private_key=wg['private_key'],
                public_key=wg['public_key'],
                port=wg.get('port', 51820),
                ipaddress=wg.get('ipaddress'),
                peer_public_key=wg.get('peer_public_key'),
                peer_endpoint=wg.get('peer_endpoint'),
                peer_allowed_ips=wg.get('peer_allowed_ips', []),
                router_id=wg['router_id'],
                status=lib_constants.PENDING_CREATE,
            )
            context.session.add(wg_db)

        return self._make_wireguard_dict(wg_db)

    def update_wireguard(self, context, wireguard_id, wireguard):
        """Update a wireguard interface."""
        wg = wireguard['wireguard']

        with db_api.CONTEXT_WRITER.using(context):
            wg_db = self._get_wireguard(context, wireguard_id)
            wg_db.update(wg)

        return self._make_wireguard_dict(wg_db)

    def delete_wireguard(self, context, wireguard_id):
        """Delete a wireguard."""
        with db_api.CONTEXT_WRITER.using(context):
            wg_db = self._get_wireguard(context, wireguard_id)
            context.session.delete(wg_db)

    @db_api.CONTEXT_READER
    def get_wireguard(self, context, wireguard_id, fields=None):
        """Get a wireguard by ID."""
        wg_db = self._get_wireguard(context, wireguard_id)
        return self._make_wireguard_dict(wg_db, fields)

    @db_api.CONTEXT_READER
    def get_wireguards(self, context, filters=None, fields=None):
        """List wireguard."""
        return model_query.get_collection(
            context,
            models.Wireguard,
            self._make_wireguard_dict,
            filters=filters,
            fields=fields,
        )

    def update_wireguard_status(self, context, wireguard_id, status):
        """Update the status of a wireguard."""
        with db_api.CONTEXT_WRITER.using(context):
            wg_db = self._get_wireguard(context, wireguard_id)
            wg_db.status = status
        return self._make_wireguard_dict(wg_db)

    def _is_peer_config_complete(self, wg):
        """Check if peer configuration is complete.

        Returns True if all required peer fields are set:
        - peer_public_key
        - peer_endpoint
        - peer_allowed_ips (non-empty)
        """
        return (wg.get('peer_public_key') and
                wg.get('peer_endpoint') and
                wg.get('peer_allowed_ips'))

    def get_wireguards_for_host(self, context, host):
        """Get all wireguards that should be configured on the given host.

        This is used by the L3 agent extension to sync wireguard
        configurations on startup or reconnection.

        Returns only wireguards with complete peer configuration that are
        associated with routers hosted on the specified host.
        """
        with db_api.CONTEXT_READER.using(context):
            agent_ids = [
                a.id for a in
                context.session.query(agent_model.Agent.id).filter_by(
                    host=host,
                    agent_type=lib_constants.AGENT_TYPE_L3,
                ).all()
            ]
            if not agent_ids:
                LOG.debug("No L3 agents found for host %s", host)
                return []

            router_ids = [
                b.router_id for b in
                context.session.query(
                    l3agent_model.RouterL3AgentBinding.router_id
                ).filter(
                    l3agent_model.RouterL3AgentBinding.l3_agent_id.in_(
                        agent_ids)
                ).all()
            ]

        if not router_ids:
            LOG.debug("No routers found on host %s", host)
            return []

        wireguards = self.get_wireguards(
            context, filters={'router_id': router_ids})
        result = [wg for wg in wireguards
                  if self._is_peer_config_complete(wg)]
        LOG.info("Returning %d wireguards for host %s", len(result), host)
        return result

    def check_router_in_use(self, context, router_id):
        """Check if a router is in use by wireguard."""
        wireguards = self.get_wireguards(
            context, filters={'router_id': [router_id]}
        )
        if wireguards:
            plural = "s" if len(wireguards) > 1 else ""
            interfaces = ",".join([w['id'] for w in wireguards])
            raise l3_exception.RouterInUse(
                router_id=router_id,
                reason="is currently used by wireguard interface%(plural)s "
                       "(%(interfaces)s)" % {'plural': plural,
                                             'interfaces': interfaces}
            )
