# Event schema

All events share one envelope (`ares.events.Event`, spec §9).

| Field | Type | Notes |
| ----- | ---- | ----- |
| `schema_version` | str | `"1.0"` |
| `event_id` | str | `evt_<ULID>` |
| `host_id` | str | stable per host (machine-id / MAC hash) |
| `boot_id` | str | new per boot (spec §25.2) |
| `timestamp_ns` | int | event time (ns) |
| `received_at` | str | ISO-8601 ingest time |
| `event_type` | enum | see below |
| `source` | str | `ebpf` \| `procfs` \| `filesystem` \| `audit` |
| `severity_hint` | float | 0..1, drives retention band + lazy enrichment |
| `process_id` | str? | reuse-safe identity |
| `user_id` | str? | `uid:<n>` or `user:<name>` |
| `container_id` | str? | when containerized |
| `payload` | dict | event-type specific fields |
| `enrichment` | dict | derived context (spec §10) |
| `redaction` | obj | `{fields_removed: [...]}` |

## Process identity (spec §7.1)

PIDs are reused, so identity is:

```
host_id:boot_id:pid:process_start_timestamp
```

Built by `ares.events.process_identity(...)`.

## Event types (spec §9.1)

`process.exec` `process.exit` `network.connect` `network.accept`
`file.create` `file.modify` `file.delete` `file.rename` `file.permission_change`
`identity.login` `identity.login_failed` `identity.user_created`
`identity.group_changed` `privilege.change` `persistence.created`
`persistence.modified` `package.installed` `package.removed`
`service.created` `service.modified` `container.started` `container.stopped`
`deployment.started` `deployment.completed`

## Accessing fields

`Event.get(key)` looks in `payload` first, then `enrichment` — rules use this so
they don't care whether a value was collected or derived.

## Example

```json
{
  "event_type": "process.exec",
  "process_id": "host_ab12:boot_77:4811:1785449655000100",
  "payload": {
    "executable": "/tmp/.update",
    "argv": ["/tmp/.update", "--password", "[REDACTED]"],
    "uid": 33,
    "parent_name": "nginx",
    "parent_is_network_service": true
  },
  "redaction": {"fields_removed": ["argv[1]"]}
}
```
