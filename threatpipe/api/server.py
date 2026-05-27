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

            handler = _ROUTES.get((method, url.path))
            if handler is None:
                return self._write(*_json(404, {"error": f"no route for {method} {url.path}"}))
            try:
                body = self._read_body()
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

        # graph endpoints ---------------------------------------
        def h_graph_stats(self, _: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            if pipeline.graph is None:
                return _json(200, {"enabled": False})
            return _json(200, {"enabled": True, **pipeline.graph.stats()})

        def h_graph_top(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            if pipeline.graph is None:
                raise _BadRequest("graph layer disabled")
            from ..graph.query import GraphQuery
            limit = int(ctx["params"].get("limit", 20))
            by = ctx["params"].get("by", "detection_score")
            items = GraphQuery(pipeline.graph).top_nodes(limit=limit, by=by)
            return _json(200, {"count": len(items), "items": items, "by": by})

        def h_graph_subgraph(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            if pipeline.graph is None:
                raise _BadRequest("graph layer disabled")
            from ..graph.query import GraphQuery
            body = ctx["body"]
            if not isinstance(body, dict) or "seeds" not in body:
                raise _BadRequest("body must contain seeds")
            seeds = [tuple(s) for s in body["seeds"] if isinstance(s, (list, tuple)) and len(s) == 2]
            depth = int(body.get("depth", 2))
            payload = GraphQuery(pipeline.graph).subgraph(seeds, depth=depth)
            return _json(200, payload)

        def h_graph_export(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            if pipeline.graph is None:
                raise _BadRequest("graph layer disabled")
            from ..graph.export import to_cyto_json, to_dot
            fmt = ctx["params"].get("format", "cyto")
            if fmt == "dot":
                return 200, {"Content-Type": "text/vnd.graphviz; charset=utf-8"}, to_dot(pipeline.graph).encode("utf-8")
            return 200, {"Content-Type": "application/json; charset=utf-8"}, to_cyto_json(pipeline.graph).encode("utf-8")

        # intel endpoints ---------------------------------------
        def h_intel_stats(self, _: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            store = _ioc_store_from_pipeline(pipeline)
            if store is None:
                return _json(200, {"enabled": False})
            return _json(200, {"enabled": True, **store.stats()})

        def h_intel_lookup(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            store = _ioc_store_from_pipeline(pipeline)
            if store is None:
                raise _BadRequest("intel layer disabled")
            from ..intel.ioc import IOCType, parse_ioc_type
            value = ctx["params"].get("value") or ""
            type_raw = ctx["params"].get("type")
            if not value:
                raise _BadRequest("missing 'value' param")
            ioc_type = None
            if type_raw:
                try:
                    ioc_type = IOCType(type_raw)
                except ValueError:
                    raise _BadRequest(f"unknown type: {type_raw}")
            else:
                ioc_type = parse_ioc_type(value)
            if ioc_type is None:
                return _json(200, {"match": None, "reason": "could not infer IOC type"})
            ioc = store.lookup(ioc_type, value)
            return _json(200, {"match": ioc.to_dict() if ioc else None})

        # incidents endpoints -----------------------------------
        def h_incident_list(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            inc_store = _incident_store(pipeline)
            if inc_store is None:
                return _json(200, {"count": 0, "items": [], "enabled": False})
            from ..incidents.model import IncidentStatus
            status_raw = ctx["params"].get("status")
            status = None
            if status_raw:
                try:
                    status = IncidentStatus(status_raw)
                except ValueError:
                    raise _BadRequest(f"unknown status: {status_raw}")
            items = inc_store.list(
                status=status,
                min_severity=ctx["params"].get("min_severity"),
                host=ctx["params"].get("host"),
                limit=int(ctx["params"].get("limit", 100)),
            )
            return _json(200, {"count": len(items), "items": [i.to_dict() for i in items]})

        def h_incident_get(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            inc_store = _incident_store(pipeline)
            inc_id = ctx["params"].get("id")
            if inc_store is None or not inc_id:
                raise _BadRequest("incident id required")
            incident = inc_store.get(inc_id)
            if incident is None:
                return _json(404, {"error": "incident not found"})
            return _json(200, incident.to_dict())

        def h_incident_timeline(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            inc_store = _incident_store(pipeline)
            inc_id = ctx["params"].get("id")
            if inc_store is None or not inc_id:
                raise _BadRequest("incident id required")
            incident = inc_store.get(inc_id)
            if incident is None:
                return _json(404, {"error": "incident not found"})
            recent = {d.event.event_id: d for d in pipeline.recent(limit=10_000)}
            from ..incidents.timeline import build_timeline
            detections = [recent[did] for did in incident.detection_ids if did in recent]
            entries = build_timeline(detections)
            return _json(200, {
                "incident_id": inc_id,
                "count": len(entries),
                "entries": [e.to_dict() for e in entries],
            })

        def h_incident_status(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            inc_store = _incident_store(pipeline)
            body = ctx["body"] or {}
            inc_id = body.get("id") or ctx["params"].get("id")
            status_raw = body.get("status")
            note = body.get("note")
            if inc_store is None or not inc_id or not status_raw:
                raise _BadRequest("id and status are required")
            from ..incidents.model import IncidentStatus
            try:
                status = IncidentStatus(status_raw)
            except ValueError:
                raise _BadRequest(f"unknown status: {status_raw}")
            incident = inc_store.update_status(inc_id, status, note=note)
            if incident is None:
                return _json(404, {"error": "incident not found"})
            return _json(200, incident.to_dict())

        # hunt endpoints ----------------------------------------
        def h_hunt_search(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            from ..hunt import HuntQuery
            body = ctx["body"] or {}
            query = body.get("query") or ctx["params"].get("query")
            target = (body.get("target") or ctx["params"].get("target") or "detections").lower()
            limit = int(body.get("limit", ctx["params"].get("limit", 100)))
            if not query:
                raise _BadRequest("query is required")
            records = _hunt_records(pipeline, target)
            hunt = HuntQuery(query, max_matches=limit)
            try:
                hunt.expr
            except SyntaxError as exc:
                raise _BadRequest(f"syntax: {exc}")
            result = hunt.run_over(records)
            return _json(200, result.to_dict())

        def h_hunt_list(self, _: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            store = _hunt_store(pipeline)
            if store is None:
                return _json(200, {"enabled": False, "count": 0, "items": []})
            return _json(200, {
                "enabled": True,
                "count": len(store),
                "items": [h.to_dict() for h in store.list()],
            })

        def h_hunt_save(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            from ..hunt import SavedHunt
            store = _hunt_store(pipeline)
            if store is None:
                raise _BadRequest("hunt store disabled")
            body = ctx["body"] or {}
            if not body.get("hunt_id") or not body.get("query"):
                raise _BadRequest("hunt_id and query are required")
            try:
                store.upsert(SavedHunt.from_dict(body))
            except (KeyError, ValueError) as exc:
                raise _BadRequest(str(exc))
            return _json(201, {"saved": body["hunt_id"]})

        def h_hunt_run(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            store = _hunt_store(pipeline)
            scheduler = getattr(pipeline, "hunt_scheduler", None)
            hunt_id = ctx["params"].get("id")
            if store is None or scheduler is None or not hunt_id:
                raise _BadRequest("hunt store, scheduler, and id are required")
            hunt = store.get(hunt_id)
            if hunt is None:
                return _json(404, {"error": "hunt not found"})
            result = scheduler.run_now(hunt)
            return _json(200, result.to_dict())

        # attck endpoints ---------------------------------------
        def h_attck_techniques(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            from ..attck import AttckCatalog
            catalog = AttckCatalog()
            search = ctx["params"].get("q")
            items = catalog.search(search) if search else catalog.all()
            return _json(200, {"count": len(items), "items": [t.to_dict() for t in items]})

        def h_attck_coverage(self, _: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            from ..attck import AttckCatalog, CoverageMap
            from ..detection.rule_engine import RuleEngine
            rules: List = []
            for det in pipeline.ensemble.detectors:
                if isinstance(det, RuleEngine):
                    rules.extend(det.rules)
            coverage = CoverageMap(AttckCatalog())
            coverage.add_rules(rules)
            return _json(200, coverage.to_dict())

        def h_attck_navigator(self, _: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            from ..attck import AttckCatalog, CoverageMap, to_navigator_layer
            from ..detection.rule_engine import RuleEngine
            rules: List = []
            for det in pipeline.ensemble.detectors:
                if isinstance(det, RuleEngine):
                    rules.extend(det.rules)
            coverage = CoverageMap(AttckCatalog())
            coverage.add_rules(rules)
            return _json(200, to_navigator_layer(coverage))

        # response endpoints ------------------------------------
        def h_response_audit(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            engine = getattr(pipeline, "response_engine", None)
            if engine is None:
                return _json(200, {"enabled": False, "count": 0, "items": []})
            limit = int(ctx["params"].get("limit", 100))
            entries = engine.audit_log.list(
                limit=limit,
                action=ctx["params"].get("action"),
                playbook_id=ctx["params"].get("playbook_id"),
                incident_id=ctx["params"].get("incident_id"),
            )
            return _json(200, {
                "enabled": True,
                "stats": engine.audit_log.stats(),
                "count": len(entries),
                "items": [e.to_dict() for e in entries],
            })

        def h_response_playbooks(self, _: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            engine = getattr(pipeline, "response_engine", None)
            if engine is None:
                return _json(200, {"enabled": False, "count": 0, "items": []})
            playbooks = engine.list_playbooks()
            return _json(200, {
                "enabled": True,
                "count": len(playbooks),
                "items": [pb.to_dict() for pb in playbooks],
            })

        # dashboard ---------------------------------------------
        def h_dashboard(self, _: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            from ..dashboard import render_dashboard
            html = render_dashboard()
            return 200, {"Content-Type": "text/html; charset=utf-8"}, html.encode("utf-8")

    # route table -------------------------------------------------
    _ROUTES: Dict[Tuple[str, str], Route] = {
        ("GET", "/health"): _Handler.h_health,
        ("GET", "/status"): _Handler.h_status,
        ("GET", "/config"): _Handler.h_config,
        ("GET", "/detections"): _Handler.h_detections,
        ("GET", "/rules"): _Handler.h_rules,
        ("POST", "/events"): _Handler.h_events,
        ("POST", "/detect"): _Handler.h_detect,
        ("GET", "/graph/stats"): _Handler.h_graph_stats,
        ("GET", "/graph/top"): _Handler.h_graph_top,
        ("POST", "/graph/subgraph"): _Handler.h_graph_subgraph,
        ("GET", "/graph/export"): _Handler.h_graph_export,
        ("GET", "/intel/stats"): _Handler.h_intel_stats,
        ("GET", "/intel/lookup"): _Handler.h_intel_lookup,
        ("GET", "/incidents"): _Handler.h_incident_list,
        ("GET", "/incidents/get"): _Handler.h_incident_get,
        ("GET", "/incidents/timeline"): _Handler.h_incident_timeline,
        ("POST", "/incidents/status"): _Handler.h_incident_status,
        ("POST", "/hunt/search"): _Handler.h_hunt_search,
        ("GET", "/hunt"): _Handler.h_hunt_list,
        ("POST", "/hunt"): _Handler.h_hunt_save,
        ("POST", "/hunt/run"): _Handler.h_hunt_run,
        ("GET", "/attck/techniques"): _Handler.h_attck_techniques,
        ("GET", "/attck/coverage"): _Handler.h_attck_coverage,
        ("GET", "/attck/navigator"): _Handler.h_attck_navigator,
        ("GET", "/response/audit"): _Handler.h_response_audit,
        ("GET", "/response/playbooks"): _Handler.h_response_playbooks,
        ("GET", "/"): _Handler.h_dashboard,
        ("GET", "/dashboard"): _Handler.h_dashboard,
    }
    return _Handler


def _hunt_records(pipeline, target: str):
    target = target.lower()
    if target == "detections":
        return pipeline.recent(limit=10_000)
    if target == "incidents":
        store = _incident_store(pipeline)
        return store.list(limit=10_000) if store else []
    if target == "events":
        # Reconstruct events from the recent detections - real deployments
        # plug an event store in via a future hook.
        return [d.event for d in pipeline.recent(limit=10_000)]
    return []


def _hunt_store(pipeline):
    return getattr(pipeline, "hunt_store", None)


def _ioc_store_from_pipeline(pipeline):
    from ..intel.matcher import IOCMatcher
    for det in pipeline.ensemble.detectors:
        if isinstance(det, IOCMatcher):
            return det.store
    return None


def _incident_store(pipeline):
    agg = getattr(pipeline, "incident_aggregator", None)
    if agg is None:
        return None
    return getattr(agg, "store", None)


class _BadRequest(Exception):
    pass


def run(pipeline: DetectionPipeline) -> ApiServer:
    server = ApiServer(pipeline)
    server.start()
    return server
