# nac-nd

> **In development** — install from source today; PyPI release planned.

CLI for change analysis on Cisco ACI fabrics via Nexus Dashboard 4.2.1+ (GA REST APIs). Upload a candidate configuration, compare snapshots, or check compliance — then fail CI when new anomalies breach your threshold.

**Requirements:** Nexus Dashboard 4.2.1+, Python 3.10+, an ACI fabric registered in Nexus Dashboard.

## Install (from source)

```bash
git clone https://github.com/netascode/nac-nd.git
cd nac-nd
uv sync --group dev
uv run nac-nd --help
```

PyPI install (`pip install nac-nd` / `uv tool install nac-nd`) will be added when the first release is published.

## Quick start

```bash
cp config.example.yaml nac-nd.yaml   # edit host, fabric
cp .env.example .env                 # set ND_PASSWORD (gitignored)
export ND_PASSWORD='...'
uv run nac-nd doctor
```

Run `nac-nd <command> --help` for all options.

## Configuration

Settings resolve in order: **CLI flags → environment variables → YAML → `.env` in cwd**.

| YAML key | Environment variable | Notes |
| --- | --- | --- |
| `host` | `ND_HOST` | Nexus Dashboard hostname |
| `username` / `user` | `ND_USER` | |
| `password` | `ND_PASSWORD` | Keep in env/CI secrets, not YAML |
| `domain` | `ND_DOMAIN` | Default `DefaultAuth` |
| `fabric` | `ND_FABRIC` | Default fabric for commands |
| `fabrics` | — | List for `compliance --all` |
| `verify_ssl` / `verify_tls` | `ND_VERIFY_SSL` | `ND_VERIFY_TLS` accepted as alias |
| `ca_bundle` | `ND_CA_BUNDLE` | |
| `job_timeout_minutes` | `ND_JOB_TIMEOUT_MINUTES` | |
| `poll_interval` | `ND_POLL_INTERVAL` | |
| `delta_detail` | `ND_DELTA_DETAIL` | Overrides `--detail` default |

Config file locations: `--config path`, `ND_CONFIG`, `./nac-nd.yaml`, or `~/.config/nac-nd/config.yaml`.

## Examples

### doctor — check connectivity

```bash
export ND_HOST=nd.example.com ND_USER=admin ND_PASSWORD='...' ND_FABRIC=FABRIC-A
nac-nd doctor
```

### prechange — Terraform plan (Network as Code)

Use with [Network as Code](https://netascode.cisco.com) projects: run `terraform plan`, export JSON, analyse before apply.

```bash
terraform plan -out=plan.tfplan
terraform show -json plan.tfplan > plan.json
nac-nd prechange plan.json --fail-on critical,major > approval.txt
echo exit code: $?
```

- **Exit 0** — DECISION: PASS  
- **Exit 3** — DECISION: FAIL (new anomalies at `--fail-on` severities)  
- Report includes a link to the Nexus Dashboard Pre-Change UI, baseline compliance, and full delta detail  
- Use `--fail-on none` to report only (always exit 0)

### prechange — APIC MO JSON

```bash
nac-nd prechange examples/minimal-change.json --output json
```

### delta — compare snapshots

```bash
nac-nd delta --prior latest-1 --later latest
nac-nd delta --prior latest-1 --later latest --output junit > delta.xml
```

`--prior` / `--later` accept `latest`, `latest-N`, or a snapshot ID. `--detail` defaults to `resources` (prechange defaults to `full`).

### compliance — rule status

```bash
nac-nd compliance
nac-nd --config nac-nd.yaml compliance --all --fail-on-violations
```

## CI/CD

Fail the stage on exit code, not by parsing the report:

```yaml
- name: Pre-change analysis
  run: |
    nac-nd prechange plan.json --fail-on critical,major > approval.txt
```

JUnit output: `--output junit` (one test case per `--fail-on` severity for prechange/delta).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success; threshold not breached |
| 1 | Unexpected error |
| 2 | Analysis job failed, stopped, vanished, or timed out |
| 3 | New anomalies at `--fail-on` (or compliance violations with `--fail-on-violations`) |
| 4 | Bad input, config, or configuration rejected by Nexus Dashboard |
| 5 | Authentication or authorisation failure |

## Limitations

- Snapshot listing returns at most 50 records; use `--since` / `--until` (ISO 8601) for older snapshots.
- Pre-change analysis creates a snapshot on the fabric that cannot be deleted via the GA API.
- The Pre-Change UI link opens the job list, not a deep link to a specific job (use `name` / `job_id` from the report to find it).
- Do not commit Terraform plans or `.env` files — they may contain credentials in variable values.

## Development

```bash
uv sync --group dev
uv run python -m pytest
uv run ruff check .
uv run ruff format --check .
uv run python -m mypy nac_nd
```

## Links

- [Analyze API](https://developer.cisco.com/docs/nexus-dashboard/latest/api-reference-analyze-analyze-overview/)
- [Manage API](https://developer.cisco.com/docs/nexus-dashboard/latest/api-reference-manage-manage-overview/)
