# DVWA image boundary

Phase 1 uses the official `ghcr.io/digininja/dvwa` image without bind-mounting
application source into the container. DVWA is attached only to the internal
`dvwa_front` and `dvwa_db` networks. It has no published port and no network
with an external gateway.

The rolling DVWA image tag is the only tag documented by the upstream project.
This repository therefore records the tested registry digest in `.env.example`.
To evaluate a deliberate upgrade, pull the tag and record its new digest:

```bash
docker image inspect ghcr.io/digininja/dvwa:latest \
  --format '{{index .RepoDigests 0}}'
```

Update `DVWA_IMAGE` only after the new digest passes the complete acceptance
suite; keep the old digest with published experiment metadata.
