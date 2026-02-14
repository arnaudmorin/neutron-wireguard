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

from neutron_lib.db import constants as db_const
from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy import orm

from neutron.db.models import l3


class Wireguard(model_base.BASEV2, model_base.HasId, model_base.HasProject):
    """Represents a wireguard."""

    __tablename__ = 'wireguards'

    name = sa.Column(sa.String(db_const.NAME_FIELD_SIZE))
    private_key = sa.Column(sa.String(44))  # wireguard base64 keys are 44 chars
    public_key = sa.Column(sa.String(44))   # Derived from private_key
    port = sa.Column(sa.Integer, default=51820)
    ipaddress = sa.Column(sa.String(64))  # CIDR notation, e.g., "10.0.0.1/24"
    peer_public_key = sa.Column(sa.String(44))
    peer_endpoint = sa.Column(sa.String(255))
    peer_allowed_ips = sa.Column(sa.JSON, default=[])
    status = sa.Column(sa.String(16), nullable=False)
    router_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('routers.id', ondelete='CASCADE'),
        nullable=False,
    )
    router = orm.relationship(l3.Router)
    agent_bindings = orm.relationship(
        'WireguardAgentBinding',
        cascade='all, delete-orphan',
        lazy='subquery',
    )


class WireguardAgentBinding(model_base.BASEV2):
    """Tracks per-agent status for a wireguard interface."""

    __tablename__ = 'wireguard_agent_bindings'

    wireguard_id = sa.Column(sa.String(36),
                             sa.ForeignKey('wireguards.id',
                                           ondelete='CASCADE'),
                             primary_key=True)
    host = sa.Column(sa.String(255), primary_key=True)
    status = sa.Column(sa.String(16), nullable=False)
