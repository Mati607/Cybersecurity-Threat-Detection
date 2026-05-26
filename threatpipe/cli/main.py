"""``threatpipe`` command-line entry point.

Sub-commands:

* ``run``      — start ingestion + detection + API and stream forever
* ``replay``   — replay a JSONL file through the pipeline once and print
                  the resulting detections
* ``rules``    — list the loaded rules (or validate a JSON rule file)
* ``parse``    — show how a single line of input would be parsed
* ``train``    — warm up ML detectors on a JSONL corpus and persist
                  them to disk
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from pathlib import Path
from typing import List, Optional

from ..alerts import build_alert_sink
from ..detection.autoencoder import AutoencoderDetector
from ..detection.isolation_forest import IsolationForestDetector
from ..detection.pipeline import DetectionPipeline
from ..detection.rule_engine import RuleEngine
from ..ingestion import (
    Event,
    FileTailSource,
    JSONLSource,
    StdinSource,
    SyslogSource,
    parse_line,
    detect_format,
)
from ..ingestion.base import EventQueue
from ..ingestion.normalizer import Normalizer
from ..utils.config import PipelineConfig, load_config
from ..utils.logging_setup import configure_logging, get_logger
from ..version import __version__

_log = get_logger(__name__)


def _make_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="threatpipe",
        description="Real-time threat detection pipeline",
    )
    p.add_argument("--version", action="version", version=f"threatpipe {__version__}")
    p.add_argument("-c", "--config", help="path to JSON config file")
    p.add_argument("--log-level", default=None, help="override log level (DEBUG/INFO/...)")
    sub = p.add_subparsers(dest="command", required=True)

    # run --------------------------------------------------------
    r = sub.add_parser("run", help="start the live pipeline")
    r.add_argument("--source", choices=["file", "syslog", "jsonl", "stdin"], default=None)
    r.add_argument("--path", help="path for file/jsonl source")
    r.add_argument("--host", help="api host override")
    r.add_argument("--port", type=int, help="api port override")
    r.add_argument("--no-api", action="store_true", help="disable the API server")
    r.add_argument("--warmup", help="JSONL file to warm up ML detectors before serving")

    # replay -----------------------------------------------------
    rp = sub.add_parser("replay", help="replay a JSONL file once and print detections")
    rp.add_argument("input", help="JSONL file to read events from")
    rp.add_argument("--warmup", help="optional warmup JSONL file")
    rp.add_argument("--limit", type=int, default=0, help="stop after N events (0 = all)")
    rp.add_argument("--json", action="store_true", help="emit detections as JSONL")

    # rules ------------------------------------------------------
    ru = sub.add_parser("rules", help="list or validate rules")
    ru.add_argument("--file", help="JSON rule file (defaults to built-in catalog)")

    # parse ------------------------------------------------------
    pa = sub.add_parser("parse", help="show how a line would be parsed")
    pa.add_argument("line", nargs="?", help="line to parse (defaults to stdin)")
    pa.add_argument("--format", help="force a specific format (json/syslog/auditd/cef)")

    # train ------------------------------------------------------
    tr = sub.add_parser("train", help="train ML detectors and save them to disk")
    tr.add_argument("input", help="JSONL file with benign-baseline events")
    tr.add_argument("--out-dir", default="./threatpipe-models", help="where to write the models")
    tr.add_argument("--epochs", type=int, default=None)
    return p


# ---------------------------------------------------------------------

def _resolve_config(args: argparse.Namespace) -> PipelineConfig:
    cfg = load_config(args.config)
    if args.log_level:
        cfg.log_level = args.log_level.upper()
    if getattr(args, "host", None):
        cfg.api.host = args.host
    if getattr(args, "port", None):
        cfg.api.port = args.port
    if getattr(args, "source", None):
        cfg.ingestion.source = args.source
    if getattr(args, "path", None):
        cfg.ingestion.path = args.path
    return cfg


def _build_source(cfg: PipelineConfig, queue: EventQueue, source: Optional[str] = None):
    src = source or cfg.ingestion.source
    n = Normalizer()
    if src == "syslog":
        return SyslogSource(queue, host=cfg.ingestion.syslog_host, port=cfg.ingestion.syslog_port, normalizer=n)
    if src == "jsonl":
        if not cfg.ingestion.path:
            raise SystemExit("jsonl source requires --path / ingestion.path")
        return JSONLSource(queue, path=cfg.ingestion.path, normalizer=n)
    if src == "stdin":
        return StdinSource(queue, normalizer=n)
    # default: file tail
    if not cfg.ingestion.path:
        raise SystemExit("file source requires --path / ingestion.path")
    return FileTailSource(
        queue,
        path=cfg.ingestion.path,
        follow=cfg.ingestion.follow,
        poll_interval=cfg.ingestion.poll_interval_s,
        normalizer=n,
    )


def _read_jsonl(path: str | Path):
    p = Path(path)
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            event = parse_line(line, fmt="json")
            if event is not None:
                yield event


# --- command handlers ---------------------------------------------

def _cmd_run(args: argparse.Namespace) -> int:
    cfg = _resolve_config(args)
    configure_logging(level=cfg.log_level, log_file=cfg.log_file)

    pipeline = DetectionPipeline(cfg, alert_sink=build_alert_sink(cfg.alerts))

    if args.warmup:
        _log.info("warming up detectors from %s", args.warmup)
        pipeline.warmup(_read_jsonl(args.warmup))

    source = _build_source(cfg, pipeline.queue)
    pipeline.start()
    source.start()

    api_server = None
    if not args.no_api:
        from ..api.server import ApiServer
        api_server = ApiServer(pipeline)
        api_server.start()

    stop = {"flag": False}

    def _stop_signal(signum, frame):
        _log.info("received signal %d, shutting down", signum)
        stop["flag"] = True

    signal.signal(signal.SIGINT, _stop_signal)
    signal.signal(signal.SIGTERM, _stop_signal)

    try:
        while not stop["flag"]:
            time.sleep(0.5)
    finally:
        if api_server is not None:
            api_server.stop()
        source.stop()
        pipeline.stop()
    return 0


def _cmd_replay(args: argparse.Namespace) -> int:
    cfg = _resolve_config(args)
    configure_logging(level=cfg.log_level)

    pipeline = DetectionPipeline(cfg)
    if args.warmup:
        pipeline.warmup(_read_jsonl(args.warmup))

    events = list(_read_jsonl(args.input))
    if args.limit:
        events = events[: args.limit]

    detections = pipeline.run_once(events)
    if args.json:
        for d in detections:
            print(json.dumps(d.to_dict(), default=str))
    else:
        for d in detections:
            print(
                f"{d.severity.value.upper():>8} score={d.score:.2f} "
                f"detector={d.detector} reason={'; '.join(d.reasons[:2])}"
            )
        print(
            f"\nProcessed {len(events)} events, "
            f"{len(detections)} detections, status={pipeline.status()}",
            file=sys.stderr,
        )
    return 0


def _cmd_rules(args: argparse.Namespace) -> int:
    engine = RuleEngine.from_json(args.file) if args.file else RuleEngine()
    for rule in engine.rules:
        print(
            f"{rule.id:<32} {rule.severity.value:<8} score={rule.score:.2f} "
            f"tags={','.join(rule.tags) or '-'}"
        )
        print(f"    {rule.description or rule.name}")
    return 0


def _cmd_parse(args: argparse.Namespace) -> int:
    line = args.line if args.line else sys.stdin.readline()
    if not line:
        print("nothing to parse", file=sys.stderr)
        return 1
    fmt = args.format or detect_format(line)
    event = parse_line(line, fmt=fmt)
    if event is None:
        print(f"could not parse line as {fmt}", file=sys.stderr)
        return 2
    out = event.to_dict()
    out["detected_format"] = fmt
    print(json.dumps(out, indent=2, default=str))
    return 0


def _cmd_train(args: argparse.Namespace) -> int:
    cfg = _resolve_config(args)
    configure_logging(level=cfg.log_level)
    events = list(_read_jsonl(args.input))
    if not events:
        print("no events in warmup file", file=sys.stderr)
        return 1
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    isofo = IsolationForestDetector(
        contamination=cfg.detection.isolation_forest_contamination,
    )
    isofo.fit(events)
    isofo.save(out_dir / "isolation_forest.pkl")

    ae = AutoencoderDetector(
        hidden=cfg.detection.autoencoder_hidden,
        epochs=args.epochs or 8,
    )
    ae.fit(events)
    ae.save(out_dir / "autoencoder.pkl")

    print(f"trained on {len(events)} events; models in {out_dir}")
    return 0


# ---------------------------------------------------------------------

_DISPATCH = {
    "run": _cmd_run,
    "replay": _cmd_replay,
    "rules": _cmd_rules,
    "parse": _cmd_parse,
    "train": _cmd_train,
}


def main(argv: Optional[List[str]] = None) -> int:
    parser = _make_parser()
    args = parser.parse_args(argv)
    handler = _DISPATCH.get(args.command)
    if handler is None:
        parser.print_help()
        return 2
    return handler(args)


if __name__ == "__main__":                                  # pragma: no cover
    sys.exit(main())
