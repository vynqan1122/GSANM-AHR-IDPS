# Phase 3 event pipeline

`collector` incrementally tails the four real JSON/JSONL sensor sinks and
publishes immutable envelopes to `security.events.raw`. `normalizer` consumes
that stream with the `normalizer` consumer group, validates a Pydantic schema,
stores events idempotently in PostgreSQL, and publishes
`security.events.normalized` only after storage succeeds.

The collector checkpoint is a named volume. New files start at EOF so enabling
the pipeline does not replay the entire Phase 2 history; rotation and
truncation are handled without resetting other sources. Retention values are
configuration only in Phase 3: cleanup is deliberately disabled.

Docker lifecycle observations already enter through Wazuh. Direct Docker
socket and local-system collectors exist as optional real inputs but remain
disabled in the default Compose profile to avoid granting another service
Docker control-plane access or misrepresenting container-local metrics as host
telemetry.

