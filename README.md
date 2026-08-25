# mmw-agent-tools

Small operational tools for an MMW Agent node.

## Restart MMW Agent

`restart-mmw-agent` performs a full systemd restart of `mmw-agent.service`, waits for a new PID, checks that the service remains active, and prints the before/after RSS and TCP connection counts. It does not restart `mmwx-guard-agent.service`.

Existing proxy connections will be interrupted briefly. Run the command as `root`.

### Install once

Install from the fixed `v1.0.0` release:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/allen0039/mmw-agent-tools/v1.0.0/restart-mmw-agent \
  -o /tmp/restart-mmw-agent

echo "5f8d640f340fc55a5c68c0a4cfe21de3aa085ef7b2a80b102edd3f73520af5df  /tmp/restart-mmw-agent" \
  | sha256sum --check --strict

sudo install -m 750 -o root -g root \
  /tmp/restart-mmw-agent \
  /usr/local/sbin/restart-mmw-agent
```

Then use:

```bash
sudo restart-mmw-agent
```

### Remote one-line execution

The following command downloads and immediately runs the fixed `v1.0.0` version:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/allen0039/mmw-agent-tools/v1.0.0/restart-mmw-agent \
  | sudo bash
```

Installing once and invoking the local command is safer than downloading a script each time.

## Requirements

- Linux with systemd
- Bash
- `iproute2` (`ss`)
- An installed `mmw-agent.service`
