# nac-nd

A CLI tool to run change analysis against Cisco ACI fabrics on Nexus Dashboard 4.2.1+. It analyses a candidate configuration, compares two snapshots or reports compliance, and exits non-zero when new anomalies breach a severity threshold.

```
$ nac-nd --help
                                                                                
 Usage: nac-nd [OPTIONS] COMMAND [ARGS]...                                      
                                                                                
 Change analysis for Cisco Nexus Dashboard 4.2.1+ (GA REST APIs, ACI).          
                                                                                
 Configuration:                                                                 
 Settings come from CLI flags, environment variables, a YAML config file, or    
 a `.env` file in the current working directory (in that order). Copy          
 `config.example.yaml` or `.env.example` to get started; you do not need to     
 `source` either file.                                                          
                                                                                
 Config file: `--config path`, `ND_CONFIG`, `./nac-nd.yaml`, or                
 `~/.config/nac-nd/config.yaml`                                                 
 Connection: ND_HOST, ND_USER, ND_PASSWORD, ND_DOMAIN, ND_FABRIC                
 Fabrics:    YAML `fabric` or `fabrics`; `compliance --all` checks each        
 Delta:      ND_DELTA_DETAIL or YAML `delta_detail` (prechange/delta only)    
 TLS:        ND_VERIFY_SSL (ND_VERIFY_TLS also accepted), ND_CA_BUNDLE          
 Timing:     ND_JOB_TIMEOUT_MINUTES, ND_POLL_INTERVAL                           
                                                                                
 Exit codes: 0 ok, 1 error, 2 job failed, 3 threshold/violation, 4 input,      
 5 auth. Run `nac-nd <command> --help` for command options.                   
                                                                                
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                  │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────╮
│ prechange   Analyse a candidate configuration against a fabric's current     │
│             state.                                                           │
│ delta       Compare two snapshots of a fabric and report what changed.       │
│ compliance  Report a fabric's compliance rule status.                        │
│ doctor      Check connectivity, credentials and fabric visibility. Changes   │
│             nothing.                                                         │
│ version     Print the version and exit.                                      │
╰──────────────────────────────────────────────────────────────────────────────╯
```

## Installation

Python 3.10+ is required to install `nac-nd`. Don't have Python 3.10 or later? See [Python 3 Installation & Setup Guide](https://realpython.com/installing-python/).

`nac-nd` can be installed using `pip`:

```
pip install nac-nd
```

or using [uv](https://docs.astral.sh/uv/):

```
uv tool install nac-nd
```

## Configuration

Settings are resolved in this order (highest wins):

1. CLI flags (`--host`, `--fabric`, …)
2. Environment variables (`ND_HOST`, `ND_PASSWORD`, …)
3. YAML config file
4. `.env` in the current working directory

You do not need to `source` a config file or `.env`; the CLI loads them automatically.

### YAML config (recommended)

Copy `config.example.yaml` to one of:

- `./nac-nd.yaml` in the directory you run commands from
- `~/.config/nac-nd/config.yaml` for a user-wide default
- Any path, passed as `nac-nd --config /path/to/nac-nd.yaml …` or via `ND_CONFIG`

Example (safe to commit — keep secrets out):

```yaml
host: nd.example.com
domain: DefaultAuth
verify_ssl: true
fabric: FABRIC-A
fabrics:
  - FABRIC-A
  - FABRIC-B
delta_detail: resources
```

Provide credentials from the environment or CI secrets:

```bash
export ND_PASSWORD='...'
nac-nd --config nac-nd.yaml doctor
```

| YAML key | Environment variable |
| --- | --- |
| `host` | `ND_HOST` |
| `username` or `user` | `ND_USER` |
| `password` | `ND_PASSWORD` (discouraged in committed files) |
| `domain` | `ND_DOMAIN` |
| `fabric` | `ND_FABRIC` |
| `fabrics` | *(list; used by `compliance --all`)* |
| `verify_ssl` or `verify_tls` | `ND_VERIFY_SSL` |
| `ca_bundle` | `ND_CA_BUNDLE` |
| `job_timeout_minutes` | `ND_JOB_TIMEOUT_MINUTES` |
| `poll_interval` | `ND_POLL_INTERVAL` |
| `delta_detail` | `ND_DELTA_DETAIL` |

If `fabrics` is omitted but `fabric` is set, `--all` uses a one-item list containing that fabric.

### `.env` (simple local use)

Copy `.env.example` to `.env` for a flat key/value file in the current directory. YAML is preferable when you have multiple fabrics or want a stable path outside cwd.

- `ND_DOMAIN` is required. `DefaultAuth` is generally accepted even though the cluster does not list it.
- Self-signed certificates need `ND_VERIFY_SSL=false`, or a CA bundle via `ND_CA_BUNDLE`.
- `ND_VERIFY_TLS` is accepted as a legacy alias when `ND_VERIFY_SSL` is unset.

## Commands

- `doctor` checks connectivity, credentials, login domains and fabric visibility. It changes nothing.
- `prechange` uploads a candidate ACI configuration, waits for the analysis and reports the anomalies it would introduce. Also takes `--base-snapshot`, `--name`, `--detail`, `--cleanup`, `--include-acknowledged` and `--output`.
- `delta` compares two snapshots. `--prior` and `--later` take `latest`, `latest-N` or a snapshot ID. `--detail` defaults to `resources`.
- `compliance` reports rule status per rule, each with a violation count. Use `--all` to check every fabric in the YAML `fabrics` list with one login.

```
nac-nd doctor
nac-nd prechange changes.json --fail-on critical,major
nac-nd delta --prior latest-1 --later latest --output junit > junit.xml
nac-nd compliance --fail-on-violations
nac-nd compliance --config nac-nd.yaml --all --fail-on-violations
```

`--all` and `--fabric` cannot be used together. Without `--all`, a single fabric comes from `--fabric`, `ND_FABRIC`, or the `fabric` key in YAML.

The snapshot listing returns at most 50 records and ignores paging parameters, so `--since` and `--until` (ISO 8601) are the way to reach older snapshots.

`prechange` reports the verdict like this:

```
command: prechange
fabric: FABRIC-A
job_id: 68b4f2a91c3d4e5f6a7b8c9d
base_snapshot_id: 0e5604f9-7270173e-664e-31fe-b3e5-eb87627aac34

New anomalies by severity:
  critical  0
  major     2
  minor     5

FAIL: New anomalies at or above the failure threshold: 2 major.
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success; no threshold was breached |
| 1 | Unexpected error |
| 2 | The analysis job failed, stopped, vanished or timed out |
| 3 | New anomalies at or above the `--fail-on` threshold (or compliance violations with `--fail-on-violations`, including across `--all`) |
| 4 | Bad input, bad configuration, or a configuration Nexus Dashboard rejected |
| 5 | Authentication or authorisation failure |

## CI/CD Integration

Arguments can be provided via command line, environment variables, or a committed YAML config with secrets injected at runtime. The tool exits non-zero when a job fails or new anomalies breach the `--fail-on` threshold. `--output junit` writes JUnit XML with one test case per severity (prechange/delta) or one testsuite per fabric (`compliance --all`).

## Known residue

- The pre-change snapshot an analysis creates cannot be deleted via the GA API and stays on the fabric.
- `--cleanup` removes the pre-change job and its `EPOCH-DELTA-ANALYSIS` children; removal is asynchronous, and anything that survives is reported as a warning.
- `GET /jobs/prechangeAnalysis/{jobId}/changedConfig` returns a gzipped tarball rather than JSON and is not exposed.

## Development

```
uv sync --group dev
uv run python -m pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy nac_nd
```

## API reference

- [Analyze API](https://developer.cisco.com/docs/nexus-dashboard/latest/api-reference-analyze-analyze-overview/)
- [Manage API](https://developer.cisco.com/docs/nexus-dashboard/latest/api-reference-manage-manage-overview/)
