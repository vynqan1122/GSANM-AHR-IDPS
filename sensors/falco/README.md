# Falco runtime IDS

The deployed configuration enables 41 rules: 25 from the pinned image and 16 maintained AHR rules scoped to the DVWA image. The AHR file is `falco_rules.local.yaml`, mounted at `/etc/falco/rules.d/90-ahr-idps.yaml`. `generated_rules.yaml` remains an empty reserved file, separate from GenTI candidates.

The modern eBPF engine captures Linux syscalls. JSON is written to stdout and the `falco_events` volume. `rule_matching: all` allows a broad stock rule and a more specific AHR rule to report the same syscall; count events by context rather than counting alerts as independent attacks.

Validate before restarting:

```powershell
docker exec ahr-idps-falco-1 falco -V /etc/falco/falco_rules.yaml -V /etc/falco/rules.d/90-ahr-idps.yaml
docker restart --timeout 30 ahr-idps-falco-1
docker logs --tail 50 ahr-idps-falco-1
```

Rules describe suspicious indicators, not proof of transfer, privilege escalation or container escape. Falco emits alerts; it does not block the host or container. [Catalog and live syscall checks](../../docs/BASELINE_RULES.md).
