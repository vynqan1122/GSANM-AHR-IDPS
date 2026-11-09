# Suricata network IDS

The active baseline has 33 alert rules: one harmless HTTP capture probe in `rules/base.rules` and 32 maintained DVWA signatures in `rules/ahr-web.rules`. `generated.rules` and `shadow.rules` remain separate and currently add no sensor signatures. These maintained rules are not GenTI model output.

`suricata.yaml` loads all four files. Capture shares the Nginx network namespace and uses PCAP/sniffer-only mode. Alerts are written to `suricata_logs` as EVE JSON. This sensor is not an inline NFQUEUE IPS.

After editing source files, validate the full configuration before restarting:

```powershell
docker exec ahr-idps-suricata-1 suricata -T --init-errors-fatal -c /etc/suricata/suricata.yaml --set unix-command.enabled=no -l /tmp
docker restart --timeout 30 ahr-idps-suricata-1
docker exec ahr-idps-suricata-1 suricatasc -c ruleset-stats /var/run/suricata/suricata-command.socket
```

URI and POST form/multipart detection are scoped to the documented paths and methods; they do not cover every encoding or body format. [Catalog and measured checks](../../docs/BASELINE_RULES.md).
