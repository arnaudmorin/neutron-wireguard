# Neutron WireGuard Extension

This is a Neutron extension/plugin that provides WireGuard VPN capabilities, allowing you to interconnect networks across different OpenStack regions using WireGuard tunnels in router namespaces.

This project also serves as an educational example for understanding how to write a Neutron plugin/extension.

## Project Structure

```
neutron_wireguard/
├── agent/                # L3 Agent Extension
│   └── wireguard.py      # Runs in neutron-l3-agent
├── cmd/                  # CLI entry points
│   └── rpc_server.py     # neutron-wireguard-rpc
├── common/               # Shared utilities
│   └── topics.py         # RPC topic definitions
├── db/                   # Database Layer
│   ├── wireguard/
│   │   ├── models.py     # SQLAlchemy models
│   │   └── db.py         # CRUD operations
│   └── migration/
│       └── alembic_migrations/
│           └── versions/
├── extensions/           # API Extension
│   └── wireguard.py      # Resource schema, validation, and extension descriptor
├── rpc/                  # RPC Layer
│   ├── server.py         # Server-side: notify agents, receive status
│   └── agent.py          # Agent-side: receive commands, report status
└── services/             # Service Plugin
    └── plugin.py         # Runs in neutron-api
```

## How this Neutron Extension Works

### Service Plugin (`services/plugin.py`)

The plugin is the main logic that execute code when a request arrives.

It will write data in the db, notify the agents about changes, etc.

This is the first file `neutron` reads when we configure the `service_plugins` correctly in `neutron.conf`.

Because the plugin is having `wireguard` in `supported_extension_aliases`, the stevedore mechanism will try to load the extension from `extensions` folder.

Note that a service plugin can live without an `extension`, but this is not our case.


### API Extension (`extensions/`)

The extension layer defines the API contract.

The extension definition is given to `neutron` thanks to the load of the plugin (the stevedore way).

The registration will tell neutron that when a request for wireguard arrives, it should be handled by a plugin that implements the methods in `WireguardPluginBase`.

Our `wireguard` plugin is implementing `WireguardPluginBase` through the `WireguardPluginDb`.

It seems complex. It is complex. It is a common pattern in neutron. Don't ask me.

### Database Layer (`db/`)

**`models.py`** - Database model

**`db.py`** - Database plugin

**`migration/`** - Alembic migrations

### RPC (`rpc/`)

This is the `Remote Procedure Call` layer that is used by the server to send notification to clients (l3 agents) and vice versa.

### Agent Extension (`agent/wireguard.py`)

The code runs on network nodes as a l3-agent extension and:
- Receives RPC notifications from the plugin
- Applies configuration to the system (writes WireGuard config files)
- Runs within router namespaceas (`snat-xyz`)

## Data Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   REST API  │────▶│   Plugin    │────▶│  Database   │     │             │
│   Request   │     │  (business  │     │   Layer     │     │             │
└─────────────┘     │   logic)    │     └─────────────┘     │             │
                    │             │                         │   Agent     │
                    │             │────── RPC ─────────────▶│  (on host)  │
                    └─────────────┘                         │             │
                                                            └─────────────┘
```

## Installation

Make sure you have `neutron_wireguard` installed in your neutron virtual env.
You can do so by running:

```bash
pip install git+https://github.com/arnaudmorin/neutron-wireguard.git
```

## Configuration

### Controller

Configure Neutron to load the service plugin in `neutron.conf`:

```ini
[DEFAULT]
service_plugins = wireguard
```

Run database migrations:

```bash
neutron-db-manage --subproject neutron-wireguard upgrade head
```

Now restart your neutron server:

```bash
# Depending on your situation, run:
systemctl restart neutron-server
# or
systemctl restart apache2
# or
systemctl restart uwsgi
# or you should know what to do :)
```

Start the `neutron-wireguard-rpc` (handles status updates from agents):

```bash
neutron-wireguard-rpc --config-file /etc/neutron/neutron.conf
```

You can also create a systemd service for it:

```ini
# /etc/systemd/system/neutron-wireguard-rpc.service
[Unit]
Description=OpenStack Neutron WireGuard RPC Server
After=network.target

[Service]
User=neutron
ExecStart=/usr/bin/neutron-wireguard-rpc --config-file /etc/neutron/neutron.conf
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable neutron-wireguard-rpc
systemctl restart neutron-wireguard-rpc
```

### Network node

Configure the L3 agent to load the l3-extension in `/etc/neutron/l3_agent.ini`:

```ini
[agent]
extensions = wireguard
```

Restart the l3 agent:

```bash
systemctl restart neutron-l3-agent
```

## API Usage

### Create a WireGuard Interface

```bash
curl -X POST http://localhost:9696/v2.0/wireguards/ \
  -H "X-Auth-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "wireguard": {
      "name": "my-wireguard",
      "router_id": "<router-uuid>",
      "port": 51820,
      "peer_public_key": "<peer-public-key>",
      "peer_endpoint": "203.0.113.1:51820",
      "peer_allowed_ips": ["10.0.0.0/24"]
    }
  }'
```

The response includes:
- `id`: UUID of the created resource
- `public_key`: Server's public key (auto-generated) - share this with peers
- `status`: Current status (PENDING_CREATE, ACTIVE, etc.)

### List WireGuard Interfaces

```bash
curl http://localhost:9696/v2.0/wireguards/ \
  -H "X-Auth-Token: $TOKEN"
```

### Neutron wireguard client

I wrote a simple neutron wireguard openstack extension for the client.

You can find it here: https://github.com/arnaudmorin/neutron-wireguard-client

## License

Apache License, Version 2.0
