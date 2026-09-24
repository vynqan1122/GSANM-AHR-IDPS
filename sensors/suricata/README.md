# Suricata Phase 2 sensor

This integration passively inspects real traffic in Nginx's Linux network
namespace. It does not use host networking, privileged mode, a synthetic event
writer, or a public target. Nginx remains the only service published to the
host, on `127.0.0.1`; DVWA remains reachable only through the isolated
`dvwa_front` bridge.

The image is pinned to the multi-architecture digest for Suricata 8.0.6:

```text
jasonish/suricata@sha256:581dca6c8cc8a8a2fafd3fff33368573b547b7600a22b21a18866da05727508f
```

Until the overlay is merged into the root Compose file, start it with:

```bash
docker compose --env-file .env \
  -f docker-compose.yml \
  -f sensors/suricata/compose.fragment.yml \
  up -d --wait --wait-timeout 180 suricata
```

Run the end-to-end acceptance test with:

```bash
bash ./scripts/suricata_acceptance.sh
```

The test sends a unique harmless path to loopback-bound Nginx and requires both
a real `http` record and a real `alert` record with SID `9000001` in
`/var/log/suricata/eve.json`. It never appends events directly. The named
`suricata_logs` volume can be mounted read-only by collectors or Wazuh.

## Runtime limits

- Live capture requires a Linux Docker Engine. Docker Desktop works because
  containers run in its Linux VM; native Windows-container mode does not.
- Rootless Docker/Podman cannot grant the packet-capture capabilities required
  by Suricata. The service is not privileged, but it needs the OISF-documented
  `NET_ADMIN`, `NET_RAW`, and `SYS_NICE` capabilities during startup and drops
  to the image's `suricata` user before processing traffic.
- `network_mode: service:nginx` intentionally limits visibility to interfaces
  in Nginx's namespace. It observes ingress and proxy-to-DVWA traffic, but it is
  not a host-wide sensor and cannot see unrelated containers or host NICs.
- Docker's embedded DNS may create `dns` events. `tls` records are enabled and
  will be emitted only when TLS actually crosses the monitored namespace; the
  current Phase 1 Nginx-to-DVWA path is plain HTTP, so an empty TLS subset is
  expected rather than fabricated.
- The sensor captures Nginx's `eth0`, `eth1`, and loopback interfaces. A logical
  request is therefore visible once on the ingress leg and once on the upstream
  leg. Downstream correlation must use interface/flow/community IDs and must not
  assume one EVE HTTP record per user request. If Nginx gains another network,
  add its new interface to the `pcap` list and rerun acceptance.

Primary references:

- <https://docs.suricata.io/en/suricata-8.0.6/security.html#containers>
- <https://docs.suricata.io/en/suricata-8.0.6/command-line-options.html>
- <https://docs.suricata.io/en/suricata-8.0.6/output/eve/eve-json-output.html>
- <https://github.com/jasonish/docker-suricata>
