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

"""add wireguard agent bindings

Revision ID: add_agent_bindings
Revises: lesamis
Create Date: 2026-02-14 00:00:00 +0000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_agent_bindings'
down_revision = 'lesamis'


def upgrade():
    op.create_table(
        'wireguard_agent_bindings',
        sa.Column('wireguard_id', sa.String(36),
                  sa.ForeignKey('wireguards.id', ondelete='CASCADE'),
                  primary_key=True),
        sa.Column('host', sa.String(255), primary_key=True),
        sa.Column('status', sa.String(16), nullable=False),
    )
