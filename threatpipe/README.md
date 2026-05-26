# threatpipe

`threatpipe` is the real-time companion to this repository's offline
explainable-IDS research code. It takes the same kinds of events the
research notebooks process in batch and runs them through a streaming
pipeline of complementary detectors, folds them into a provenance
graph, enriches them with threat intel, and surfaces the result as
correlated incidents with kill-chain projections.

```
┌──────────┐     ┌──────────────┐     ┌────────────────────────────────┐     ┌────────────┐
│  Source  │ ──▶ │   Parsers    │ ──▶ │  Ensemble                      │ ──▶ │  Alert     │
│  (file,  │     │  + Normalizer│     │   rules  + stat. + iforest +   │     │  sinks     │
│  syslog, │     │              │     │   autoencoder (weighted_mean)  │     │ (stdout,   │
│  jsonl,  │     │              │     │                                │     │  file,     │
│  stdin)  │     │              │     │                                │     │  webhook,  │
└──────────┘     └──────────────┘     └────────────────────────────────┘     │  slack,    │
                                                                              │  email)    │
                                                                              └────────────┘
```

## Quick start

```bash
# show the bundled rule catalog
python -m threatpipe rules

# replay a JSONL file through the pipeline once and print detections
python -m threatpipe replay path/to/events.jsonl

# start the live pipeline against a log file, plus the REST API
python -m threatpipe run --source file --path /var/log/auth.log
```

## Configuration

`load_config()` reads `--config` JSON first, then applies environment
overrides of the form `THREATPIPE_<SECTION>_<FIELD>` (uppercase). All
fields on `PipelineConfig` and its sub-dataclasses are addressable
this way.

```json
{
    "detection": {
        "engines": ["rule", "statistical", "isolation_forest"],
        "score_threshold": 0.6,
        "ensemble_strategy": "weighted_mean"
    },
    "alerts": {
        "channels": ["stdout", "slack"],
        "min_severity": "high",
        "slack_token": "xoxb-...",
        "slack_channel": "#alerts-sec"
    },
    "api": {
        "host": "127.0.0.1",
        "port": 8088,
        "api_key": "rotate-me"
    }
}
```

## REST API

| Method | Path                     | Purpose                                              |
| ------ | ------------------------ | ---------------------------------------------------- |
| GET    | `/health`                | Liveness probe                                       |
| GET    | `/status`                | Counters (events_in, detections_out, ...)            |
| GET    | `/config`                | Effective configuration, secrets redacted            |
| GET    | `/detections`            | Recent detections (`?limit=`)                        |
| GET    | `/rules`                 | Loaded rule catalog                                  |
| POST   | `/events`                | Ingest one event or a list of events                 |
| POST   | `/detect`                | Synchronously classify a single event                |
| GET    | `/graph/stats`           | Node/edge counts in the provenance graph             |
| GET    | `/graph/top`             | Top nodes by `detection_score` / `centrality` / ...  |
| POST   | `/graph/subgraph`        | BFS subgraph around `seeds`                          |
| GET    | `/graph/export`          | Cytoscape JSON or DOT (`?format=dot`)                |
| GET    | `/intel/stats`           | IOC store size, grouped by type and source           |
| GET    | `/intel/lookup`          | Look up a single indicator (`?value=&type=`)         |
| GET    | `/incidents`             | List incidents (`?status=&min_severity=&host=`)      |
| GET    | `/incidents/get`         | Fetch a single incident (`?id=`)                     |
| GET    | `/incidents/timeline`    | Build a timeline view for an incident                |
| POST   | `/incidents/status`      | Acknowledge / contain / resolve / mark FP            |

Pass `X-Api-Key` (or `Authorization: Bearer <key>`) when an api key is
configured. CORS origins are configurable per deployment.

## Detection engines

* **rule** — declarative MITRE-tagged rule catalog (`RuleEngine`)
* **statistical** — per-host EWMA over event-rate, unique destination
  ports, unique processes, outbound bytes
* **isolation_forest** — pure-Python Liu-et-al. Isolation Forest with
  pickle persistence
* **autoencoder** — MLP reconstruction-error detector, also pure
  Python, persistable
* **ioc** — threat-intel matcher against the `IOCStore` (network
  endpoints, file paths, processes/users, plus regex-extracted
  domains and hashes from `command_line` / `message`)

All five are composed by `EnsembleDetector` with `weighted_mean`,
`max`, or `majority` strategies, and emit a single, deduplicated
`Detection` object with explanation chain for downstream review.

## Provenance graph

Every event is folded into an in-memory `ProvenanceGraph`
(`threatpipe.graph`) modeling hosts, processes, users, files, and
sockets with `SPAWNED`/`EXECUTED`/`READ`/`WROTE`/`CONNECTED`/
`AUTHENTICATED` edges. The graph is bounded (`max_nodes`, per-source
fanout cap, `expire_older_than` TTL sweep) and exposes BFS subgraph
extraction, detection-weighted degree centrality, and a
`suspicious_paths` walker that rewards exec→connect→remote-socket
chains. DOT and Cytoscape.js exporters drop straight into a SOC
dashboard.

## Threat intel

`threatpipe.intel` adds a thread-safe `IOCStore` populated from CSV,
JSON, JSONL, STIX-lite, or hosts-style feeds (`load_feed`). The
`IOCMatcher` detector slots straight into the ensemble. A
`ReputationCache` with TTL eviction memoizes per-(kind, value)
lookups from a pluggable resolver, and `enrich_event` /
`enrich_detection` attach IOC hits and reputation metadata to alert
payloads.

## Incidents and kill chain

Correlated detections roll up into `Incident` objects via
`GraphCorrelator` + `IncidentAggregator`. The aggregator only
promotes a correlation group once it crosses a score+severity floor
or a detection-count threshold, and keeps the kill-chain projection
up to date. `infer_phase` maps MITRE technique tags and free-form
labels ("persistence", "c2", "ransomware", ...) onto Lockheed-Martin
phases; `build_timeline` produces an audit-trail view with
escalation markers for analyst hand-off.

## Testing

```bash
pip install -e ".[test]"
pytest
```
