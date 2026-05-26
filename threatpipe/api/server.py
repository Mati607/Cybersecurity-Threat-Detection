"""Stdlib-only HTTP server exposing the running detection pipeline.

We keep this on ``http.server`` rather than pulling in FastAPI/Flask so
the on-line service has zero runtime dependencies outside the Python
standard library. The handler is small enough that a router-by-tuple
is more readable than mini-frameworks.

Endpoints
---------

* ``GET  /health``         — liveness probe
* ``GET  /status``         — counters from the pipeline metrics
* ``GET  /config``         — current effective config (redacted)
* ``GET  /detections``     — most recent detections (``?limit=50``)
* ``GET  /rules``          — installed rule catalog
* ``POST /events``         — ingest one event or a list of events (JSON body)
* ``POST /detect``         — run detectors over a body event without
                              persisting it; useful for unit-style API tests
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from ..detection.pipeline import DetectionPipeline
from ..detection.rule_engine import RuleEngine
from ..ingestion.event import Event
from ..utils.config import PipelineConfig
from ..utils.logging_setup import get_logger
from ..version import __version__

_log = get_logger(__name__)


Route = Callable[["_Handler", Dict[str, Any]], Tuple[int, Dict[str, str], bytes]]


def _json(status: int, payload: Any) -> Tuple[int, Dict[str, str], bytes]:
    body = json.dumps(payload, default=str).encode("utf-8")
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": str(len(body)),
    }
    return status, headers, body


def _redact_config(cfg: PipelineConfig) -> Dict[str, Any]:
    raw = cfg.to_dict()
    alerts = raw.get("alerts", {})
    for key in ("slack_token", "webhook_url", "email_smtp_host"):
        if alerts.get(key):
            alerts[key] = "***"
    if raw.get("api", {}).get("api_key"):
        raw["api"]["api_key"] = "***"
    return raw


class ApiServer:
    """Wrapper that owns the http server thread + the pipeline reference."""

    def __init__(self, pipeline: DetectionPipeline) -> None:
        self.pipeline = pipeline
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        cfg = self.pipeline.config.api
        handler_cls = _build_handler(self.pipeline)
        self._server = ThreadingHTTPServer((cfg.host, cfg.port), handler_cls)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        _log.info("api listening on http://%s:%d", cfg.host, cfg.port)

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None


def build_app(pipeline: DetectionPipeline) -> type:
    """Return a handler class bound to ``pipeline``. Useful for tests."""
    return _build_handler(pipeline)


def _build_handler(pipeline: DetectionPipeline) -> type:
    config = pipeline.config

    class _Handler(BaseHTTPRequestHandler):
        server_version = f"threatpipe/{__version__}"

        # silence the default per-request access log; we have our own logger.
        def log_message(self, fmt: str, *args: Any) -> None:    # noqa: A003
            _log.debug("%s - " + fmt, self.address_string(), *args)

        # auth ----------------------------------------------------
        def _authorized(self) -> bool:
            required = config.api.api_key
            if not required:
                return True
            provided = self.headers.get("X-Api-Key") or ""
            if not provided and self.headers.get("Authorization", "").startswith("Bearer "):
                provided = self.headers["Authorization"][len("Bearer "):]
            return provided == required

        # CORS ---------------------------------------------------
        def _send_cors(self) -> None:
            origins = config.api.cors_origins
            if origins:
                origin = self.headers.get("Origin", "*")
                allow = origin if origin in origins or "*" in origins else origins[0]
                self.send_header("Access-Control-Allow-Origin", allow)
                self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Api-Key, Authorization")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

        # dispatch ----------------------------------------------
        def do_OPTIONS(self) -> None:                       # noqa: N802
            self.send_response(204)
            self._send_cors()
            self.end_headers()

        def do_GET(self) -> None:                           # noqa: N802
            self._dispatch("GET")

        def do_POST(self) -> None:                          # noqa: N802
            self._dispatch("POST")

        def _dispatch(self, method: str) -> None:
            if not self._authorized():
                return self._write(*_json(401, {"error": "unauthorized"}))

            url = urlparse(self.path)
            params = {k: v[0] for k, v in parse_qs(url.query).items()}
            body = self._read_body()

            handler = _ROUTES.get((method, url.path))
            if handler is None:
                return self._write(*_json(404, {"error": f"no route for {method} {url.path}"}))
            try:
                status, headers, payload = handler(self, {"params": params, "body": body})
            except _BadRequest as exc:
                status, headers, payload = _json(400, {"error": str(exc)})
            except Exception:                               # pragma: no cover
                _log.exception("handler crashed")
                status, headers, payload = _json(500, {"error": "internal server error"})
            self._write(status, headers, payload)

        def _read_body(self) -> Any:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length == 0:
                return None
            raw = self.rfile.read(length)
            ctype = self.headers.get("Content-Type", "")
            if "application/json" in ctype or raw.startswith(b"{") or raw.startswith(b"["):
                try:
                    return json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise _BadRequest(f"invalid json: {exc}") from None
            return raw

        def _write(self, status: int, headers: Dict[str, str], body: bytes) -> None:
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self._send_cors()
            self.end_headers()
            if body:
                self.wfile.write(body)

        # handlers ---------------------------------------------
        def h_health(self, _: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            return _json(200, {"status": "ok", "version": __version__})

        def h_status(self, _: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            return _json(200, pipeline.status())

        def h_config(self, _: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            return _json(200, _redact_config(pipeline.config))

        def h_detections(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            try:
                limit = int(ctx["params"].get("limit", 100))
            except ValueError:
                raise _BadRequest("limit must be an integer")
            limit = max(1, min(1000, limit))
            items = [d.to_dict() for d in pipeline.recent(limit=limit)]
            return _json(200, {"count": len(items), "items": items})

        def h_rules(self, _: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            engine: Optional[RuleEngine] = None
            for det in pipeline.ensemble.detectors:
                if isinstance(det, RuleEngine):
                    engine = det
                    break
            if engine is None:
                return _json(200, {"count": 0, "items": []})
            items = [{
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "score": r.score,
                "severity": r.severity.value,
                "tags": list(r.tags),
                "fields": list(r.where.keys()),
            } for r in engine.rules]
            return _json(200, {"count": len(items), "items": items})

        def h_events(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            body = ctx["body"]
            if body is None:
                raise _BadRequest("missing JSON body")
            events = body if isinstance(body, list) else [body]
            accepted = 0
            for raw in events:
                try:
                    pipeline.queue.put(Event.from_dict(raw))
                    accepted += 1
                except TypeError as exc:
                    raise _BadRequest(f"invalid event: {exc}") from None
            return _json(202, {"accepted": accepted})

        def h_detect(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            body = ctx["body"]
            if body is None or not isinstance(body, dict):
                raise _BadRequest("body must be a JSON object")
            event = Event.from_dict(body)
            detection = pipeline.ensemble.detect(event)
            return _json(200, {
                "detection": detection.to_dict() if detection else None,
            })

    # route table -------------------------------------------------
    _ROUTES: Dict[Tuple[str, str], Route] = {
        ("GET", "/health"): _Handler.h_health,
        ("GET", "/status"): _Handler.h_status,
        ("GET", "/config"): _Handler.h_config,
        ("GET", "/detections"): _Handler.h_detections,
        ("GET", "/rules"): _Handler.h_rules,
        ("POST", "/events"): _Handler.h_events,
        ("POST", "/detect"): _Handler.h_detect,
    }
    return _Handler


class _BadRequest(Exception):
    pass


def run(pipeline: DetectionPipeline) -> ApiServer:
    server = ApiServer(pipeline)
    server.start()
    return server
