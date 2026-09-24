# Wazuh Phase 2 lab integration

This overlay runs the official Wazuh 4.14.7 manager without an indexer or
dashboard. It provides a real SIEM analysis boundary at
`/var/ossec/logs/alerts/alerts.json`, persists manager state, consumes
Suricata EVE JSON and Falco JSONL, and monitors Docker Engine events through
Wazuh's bundled Docker listener.

The default overlay exposes agent transport and enrollment only on loopback
(`1514` and `1515`). To expose the manager API for local control, add the
optional API fragment:

```bash
bash scripts/start_wazuh_api.sh
```

The API is then available at `https://127.0.0.1:55000`; it remains loopback-only
and the full Wazuh indexer/dashboard stack is intentionally outside this small
DVWA lab.

## Start

Create the untracked enrollment secret, then merge all Phase 2 fragments:

```bash
bash scripts/wazuh_prepare.sh
docker compose --env-file .env \
  -f docker-compose.yml \
  -f sensors/suricata/compose.fragment.yml \
  -f sensors/falco/compose.fragment.yml \
  -f sensors/wazuh/compose.fragment.yml \
  up -d --wait --wait-timeout 300
```

Only agent transport (`127.0.0.1:1514/tcp`) and password-protected enrollment
(`127.0.0.1:1515/tcp`) are published. The API, indexer, and dashboard are not
published or included.

Run the real-event acceptance test:

```bash
bash scripts/wazuh_acceptance.sh
```

It creates and removes a marker container, sends a marker HTTP request through
Nginx for Suricata SID 9000001, and launches a marker shell in DVWA for Falco.
It succeeds only when fresh Wazuh JSON alerts prove all three paths. Use
`--docker-only` to diagnose the manager independently of the two sensors.

## Native Windows host and authentication events

A Wazuh agent inside a container cannot monitor its container host. On Docker
Desktop, mounting `/var/log` would expose the Linux VM, not Windows Security
events. Install the signed Wazuh 4.14.7 Windows agent on the host and point it
at `127.0.0.1`; its default configuration monitors the System, Security, and
Application event channels.

Download the 4.14.7 MSI from the official Wazuh packages page. In an elevated
PowerShell session, use the private value from
`sensors/wazuh/secrets/authd.pass` without committing or printing it:

```powershell
msiexec.exe /i .\wazuh-agent-4.14.7-1.msi /q `
  WAZUH_MANAGER="127.0.0.1" `
  WAZUH_REGISTRATION_SERVER="127.0.0.1" `
  WAZUH_REGISTRATION_PASSWORD="<private value>"
Start-Service wazuhsvc
```

Then run the strict host/auth gate from Git Bash or WSL:

```bash
bash scripts/wazuh_acceptance.sh --require-host-auth
```

That option requires a non-manager active agent and invokes
`wazuh_auth_probe.ps1`, which makes one controlled failed Windows logon using a
unique nonexistent username. It passes only after that real Security event is
received and mapped to a Wazuh authentication-failure alert. The ordinary
acceptance command does **not** claim Windows host/auth coverage.

## Resources and security boundary

The manager-only service is capped at 2 CPUs and 1.5 GiB RAM (512 MiB
reservation); allow at least 10 GiB free for retained manager state and alerts.
The complete supported Wazuh single-node deployment (manager, indexer, and
dashboard) has a materially larger official minimum of 4 CPU cores, 8 GiB RAM,
and 50 GB storage. It also requires the indexer's `vm.max_map_count`; this
manager-only topology does not.

The Docker socket is effectively root-equivalent access to the Docker daemon.
The `:ro` bind protects the socket inode but does not make Docker API methods
read-only. This is a deliberate lab trust boundary required for real Docker
event collection; do not expose this manager to untrusted workloads.

## Primary references

- Wazuh Docker 4.14.7 release: <https://github.com/wazuh/wazuh-docker/releases/tag/v4.14.7>
- Wazuh Docker deployment requirements: <https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html>
- Docker monitoring: <https://documentation.wazuh.com/current/user-manual/capabilities/container-security/monitoring-docker.html>
- Docker real-event proof of concept: <https://documentation.wazuh.com/current/proof-of-concept-guide/monitoring-docker.html>
- Suricata integration: <https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html>
- Windows deployment variables: <https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/deployment-variables/deployment-variables-windows.html>
- Agent log collection: <https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html>
- Falco JSON output fields: <https://falco.org/docs/concepts/outputs/channels/>
