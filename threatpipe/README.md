# threatpipe

`threatpipe` is the real-time companion to this repository's offline
explainable-IDS research code. It takes the same kinds of events the
research notebooks process in batch and runs them through a streaming
pipeline of complementary detectors, emitting actionable alerts.

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

| Method | Path           | Purpose                                     |
| ------ | -------------- | ------------------------------------------- |
| GET    | `/health`      | Liveness probe                              |
| GET    | `/status`      | Counters (events_in, detections_out, ...)   |
| GET    | `/config`      | Effective configuration, secrets redacted   |
| GET    | `/detections`  | Recent detections (`?limit=`)               |
| GET    | `/rules`       | Loaded rule catalog                         |
| POST   | `/events`      | Ingest one event or a list of events        |
| POST   | `/detect`      | Synchronously classify a single event       |

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

All four are composed by `EnsembleDetector` with `weighted_mean`,
`max`, or `majority` strategies, and emit a single, deduplicated
`Detection` object with explanation chain for downstream review.

## Testing

```bash
pip install -e ".[test]"
pytest
```
