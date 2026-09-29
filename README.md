# SNMP Trap Receiver for the OpenTelemetry Collector

| Status | |
| --- | --- |
| Stability | development: logs |
| Distributions | none yet, build with [ocb](#build-a-collector-with-it) |
| Contrib donation | [open-telemetry/opentelemetry-collector-contrib#50849](https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/50849) (draft, sponsor needed) |
| Tracking issue | [open-telemetry/opentelemetry-collector-contrib#32358](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/32358) |
| Code owner | [@Mesverrum](https://github.com/Mesverrum) |

The SNMP Trap Receiver listens for SNMPv1/v2c (optional v3 USM) traps and
informs over UDP and converts each PDU to an OpenTelemetry **log**.

A trap is an event (linkDown, coldStart, vendor fault). Emitting a metric series
per trap OID/source is the wrong signal. Volume for dashboards is log count.

This module is the collector-shaped core of `otelcol.receiver.snmptrap`, which
already runs in [Mesverrum/alloy](https://github.com/Mesverrum/alloy) on a lab
fabric. The Alloy-only pieces (targets, device join, Fleet) are not here. The
same code is up for donation to contrib in
[#50849](https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/50849);
this repository is the standalone home the contrib process asks for while that
PR looks for a sponsor.

## Looking for a sponsor and codeowners

The contrib donation needs a sponsor (an approver or maintainer at a company
other than mine) and two more codeowners. If you run traps in production and
want a listener in the collector, open an issue here or comment on
[#50849](https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/50849).
I will keep maintaining the implementation either way.

## Build a collector with it

Until the donation lands, include the receiver with the
[OpenTelemetry Collector Builder](https://opentelemetry.io/docs/collector/custom-collector/).
`builder-config.yaml` in this repo is a working manifest:

```shell
go install go.opentelemetry.io/collector/cmd/builder@v0.160.0
builder --config builder-config.yaml
./dist/otelcol-snmptrap --config example-config.yaml
```

Then point a device trap-group at the collector host and port and watch the
debug exporter. `example-config.yaml` lists every setting with its default.

By default the receiver binds `0.0.0.0:1620`. Privileged `:162` needs
`CAP_NET_BIND_SERVICE` or DNAT.

```yaml
receivers:
  snmptrap:
    listen_address: 0.0.0.0:1620
    # empty communities = accept all (common field practice)
    communities: [public]
    mib_paths: [/etc/snmp/mibs]
    attributes:
      job: snmptrap

exporters:
  debug:
    verbosity: detailed

service:
  pipelines:
    logs:
      receivers: [snmptrap]
      exporters: [debug]
```

## Configuration

| Field | Description | Default |
| --- | --- | --- |
| `listen_address` | UDP bind host:port | `0.0.0.0:1620` |
| `communities` | v1/v2c allowlist. Empty = accept all | `[]` |
| `include_community` | Put the community string on the log (off by default) | `false` |
| `drop_undefined` | Drop traps whose trap OID did not resolve via MIBs | `false` |
| `mib_paths` | Directories of SMI/MIB files for gosmi name enrichment | `[]` |
| `attributes` | Extra log attributes stamped on every record | `{}` |
| `v3` | Optional USM user. When set, the listener is v3-only | unset |

### `v3`

| Field | Description |
| --- | --- |
| `user` | USM user (required when `v3` is set) |
| `security_level` | `noAuthNoPriv` (default), `authNoPriv`, `authPriv` |
| `auth_protocol` | `MD5`, `SHA`, `SHA224`, `SHA256`, `SHA384`, `SHA512` |
| `auth_password` | Auth passphrase |
| `priv_protocol` | `DES`, `AES`, `AES192`, `AES192C`, `AES256`, `AES256C` |
| `priv_password` | Privacy passphrase |

gosnmp still documents v3 trap listen as less battle-tested than v2c.

## Data format

Each PDU becomes one log record.

**Body:** compact JSON (`source`, `trap_oid`, `trap_name`, `varbinds`, …).

**Attributes:** `source`, `trap_oid`, `trap_name`, `trap_mib`, `snmp_version`,
`pdu_type`, plus any `attributes` map entries. Optional `agent_address`,
`engine_id`, `context_name`, `community`.

**Timestamps:** `Timestamp` is receive time; `ObservedTimestamp` is now.

MIB lookup is fail-open. Missing names stay numeric OIDs.

UDP receive never blocks: a full in-memory queue drops the trap.

## Development

```shell
make test     # go test ./...
make cover    # coverage summary
make lint     # go vet + gofmt check
make generate # regenerate internal/metadata from metadata.yaml
```

Layout follows a contrib receiver so the code moves into
`receiver/snmptrapreceiver` unchanged apart from the module path.

## License

Apache 2.0. See [LICENSE](LICENSE). Files carry the OpenTelemetry Authors
header because they are written for donation to the OpenTelemetry project.
