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

from oslo_config import cfg

WIREGUARD_OPTS = [
    cfg.IntOpt('periodic_sync_interval',
               default=300,
               min=0,
               help='Interval in seconds between periodic wireguard sync '
                    'runs. Set to 0 to disable periodic sync.'),
    cfg.IntOpt('sync_max_workers',
               default=10,
               min=1,
               help='Maximum number of threads for parallel wireguard sync.'),
]


def register_wireguard_opts(conf=cfg.CONF):
    conf.register_opts(WIREGUARD_OPTS, 'wireguard')
