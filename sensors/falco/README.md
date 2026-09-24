# Falco Phase 2 integration

This integration runs the official Falco 0.44.1 Debian image with the bundled
modern eBPF driver. It consumes Linux kernel syscalls and writes native Falco
JSON Lines to both container stdout and `/var/log/falco/events.jsonl` on the
`falco_events` named volume. No alert fixture or synthetic event producer is
included. Falco uses `rule_matching: all` because upstream and project-specific
rules can validly match the same syscall; without it, an earlier upstream rule
can shadow an AHR-IDPS alert.

`compose.fragment.yml` is a merge-ready service fragment. The main Compose file
must contain the same `falco` service and `falco_events` volume (or be invoked
with both Compose files) before the scripts can start it:

```bash
bash scripts/falco_acceptance.sh
```

The acceptance script starts only `falco` with `--no-deps`. It requires the
Phase 1 DVWA service to be running already and never changes the vulnerable
lab's lifecycle. The Falco service itself has `restart: "no"` for the same
manual opt-in safety boundary.

The fragment uses the multi-platform digest for the official
`0.44.1-debian` image. The distroless `0.44.1` equivalent is
`sha256:d0cfe422d6ac0e0f20857798f46c7d7273210e1b064b22821e4e6e7f843cde6b`;
the Debian variant is intentional because its publisher installs `curl` and
`jq`, enabling an in-container readiness probe and JSON acceptance checks.

On native Linux, tracefs is commonly `/sys/kernel/tracing`. Docker Desktop's
Linux VM exposes it at `/sys/kernel/debug/tracing`, which is the source mounted
by this fragment. If a native Linux host lacks that path, change only the mount
source to `/sys/kernel/tracing`. The container destination remains
`/sys/kernel/tracing`.

The unavoidable platform boundary is the Linux kernel: on Windows or macOS,
Falco observes the Docker Desktop Linux VM and its Linux containers, not Windows
or macOS host processes. Modern eBPF requires BPF ring buffers and kernel BTF
(normally Linux 5.8+). Docker Desktop Enhanced Container Isolation and rootless
Docker can intentionally prevent the host PID/capability access Falco needs;
run this isolated research lab with ECI disabled or install Falco directly on a
separate Linux VM/host. The Docker socket is mounted read-only at the filesystem
level, but socket access is daemon-equivalent privilege, so the Falco service
must be treated as a trusted host sensor.

For Wazuh or the Phase 3 collector, mount
`falco_events:/var/log/falco:ro` and tail
`/var/log/falco/events.jsonl` as JSON. Each line is a native Falco event with
`time`, `rule`, `priority`, `source`, `hostname`, `tags`, `output`, `message`,
and `output_fields`.
