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
#

"""start neutron-wireguard chain

Revision ID: lesamis
Revises: None
Create Date: Wed, 04 Feb 2026 22:56:34 +0100

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'lesamis'
down_revision = None


def upgrade():
    op.create_table(
        'wireguards',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('project_id', sa.String(255), index=True),
        sa.Column('name', sa.String(255)),
        sa.Column('private_key', sa.String(44)),
        sa.Column('public_key', sa.String(44)),
        sa.Column('port', sa.Integer, default=51820),
        sa.Column('ipaddress', sa.String(64)),
        sa.Column('peer_public_key', sa.String(44)),
        sa.Column('peer_endpoint', sa.String(255)),
        sa.Column('peer_allowed_ips', sa.JSON, default=[]),
        sa.Column('router_id', sa.String(36),
                  sa.ForeignKey('routers.id', ondelete='CASCADE'),
                  nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
    )
