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

        # forensics endpoints -----------------------------------
        def h_forensics_stats(self, _: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            store = _forensics_store(pipeline)
            if store is None:
                return _json(200, {"enabled": False})
            return _json(200, {"enabled": True, **store.stats()})

        def h_forensics_search(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            store = _forensics_store(pipeline)
            if store is None:
                raise _BadRequest("forensics layer disabled")
            from ..forensics import ForensicsQuery, TimeRange
            params = ctx["params"]
            tr = TimeRange(
                since=_opt_float(params.get("since")),
                until=_opt_float(params.get("until")),
            )
            items = ForensicsQuery(store).search_detections(
                range=tr,
                host=params.get("host"),
                severity=params.get("severity"),
                detector=params.get("detector"),
                limit=int(params.get("limit", 100)),
            )
            return _json(200, {"count": len(items), "items": items})

        def h_forensics_histogram(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            store = _forensics_store(pipeline)
            if store is None:
                raise _BadRequest("forensics layer disabled")
            from ..forensics import ForensicsQuery, TimeRange
            params = ctx["params"]
            since = _opt_float(params.get("since"))
            until = _opt_float(params.get("until"))
            if since is None or until is None:
                raise _BadRequest("since and until are required")
            agg = ForensicsQuery(store).detections_histogram(
                range=TimeRange(since=since, until=until),
                bin_seconds=int(params.get("bin_seconds", 60)),
            )
            return _json(200, agg.to_dict())

        # simulator endpoints -----------------------------------
        def h_sim_scenarios(self, _: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            from ..simulator import list_scenarios
            items = [s.to_dict() for s in list_scenarios()]
            return _json(200, {"count": len(items), "items": items})

        def h_sim_run(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            from ..simulator import (
                SimulationEngine, get_scenario, evaluate_detection_coverage,
            )
            body = ctx["body"] or {}
            scenario_id = body.get("scenario") or ctx["params"].get("scenario")
            if not scenario_id:
                raise _BadRequest("scenario is required")
            try:
                scenario = get_scenario(scenario_id)
            except KeyError:
                return _json(404, {"error": f"unknown scenario: {scenario_id}"})
            engine = SimulationEngine(pipeline)
            result = engine.run(scenario, host=body.get("host", "victim01"),
                                user=body.get("user", "jdoe"))
            report = evaluate_detection_coverage(scenario, result)
            return _json(200, {"result": result.to_dict(), "coverage": report.to_dict()})

        # case endpoints ----------------------------------------
        def h_cases_list(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            mgr = getattr(pipeline, "case_manager", None)
            if mgr is None:
                return _json(200, {"enabled": False, "count": 0, "items": []})
            from ..cases import CasePriority, CaseStatus
            params = ctx["params"]
            status = _enum_or_none(CaseStatus, params.get("status"))
            priority = _enum_or_none(CasePriority, params.get("priority"))
            cases = mgr.store.list(
                status=status, priority=priority,
                assignee=params.get("assignee"),
                open_only=params.get("open_only") == "true",
                limit=int(params.get("limit", 100)),
            )
            return _json(200, {"enabled": True, "count": len(cases),
                                "items": [c.to_dict() for c in cases]})

        def h_cases_get(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            mgr = getattr(pipeline, "case_manager", None)
            case_id = ctx["params"].get("id")
            if mgr is None or not case_id:
                raise _BadRequest("case id required")
            case = mgr.get(case_id)
            if case is None:
                return _json(404, {"error": "case not found"})
            return _json(200, case.to_dict())

        def h_cases_create(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            mgr = getattr(pipeline, "case_manager", None)
            if mgr is None:
                raise _BadRequest("case manager disabled")
            body = ctx["body"] or {}
            if not body.get("title"):
                raise _BadRequest("title is required")
            from ..cases import CasePriority
            case = mgr.open_case(
                title=body["title"],
                reporter=body.get("reporter", "api"),
                description=body.get("description", ""),
                priority=_enum_or_none(CasePriority, body.get("priority")) or CasePriority.P3,
                incident_ids=body.get("incident_ids", []),
                tags=body.get("tags", []),
            )
            return _json(201, case.to_dict())

        def h_cases_note(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            mgr = getattr(pipeline, "case_manager", None)
            body = ctx["body"] or {}
            if mgr is None or not body.get("id") or not body.get("body"):
                raise _BadRequest("id and body are required")
            note = mgr.add_note(body["id"], body.get("author", "api"), body["body"])
            if note is None:
                return _json(404, {"error": "case not found"})
            return _json(201, note.to_dict())

        # compliance endpoints ----------------------------------
        def h_compliance_frameworks(self, _: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            from ..compliance import list_frameworks
            items = [{"framework_id": f.framework_id, "name": f.name,
                      "version": f.version, "control_count": len(f.controls)}
                     for f in list_frameworks()]
            return _json(200, {"count": len(items), "items": items})

        def h_compliance_report(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            from ..compliance import build_compliance_report, get_framework
            from ..detection.rule_engine import RuleEngine
            framework_id = ctx["params"].get("framework", "nist-800-53")
            try:
                framework = get_framework(framework_id)
            except KeyError:
                return _json(404, {"error": f"unknown framework: {framework_id}"})
            rules: List = []
            for det in pipeline.ensemble.detectors:
                if isinstance(det, RuleEngine):
                    rules.extend(det.rules)
            return _json(200, build_compliance_report(framework, rules))

        # model registry ----------------------------------------
        def h_models_summary(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            reg = getattr(pipeline, "model_registry", None)
            if reg is None:
                return _json(200, {"enabled": False, "model_count": 0, "total_versions": 0, "models": {}})
            return _json(200, reg.summary())

        def h_models_list(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            reg = getattr(pipeline, "model_registry", None)
            if reg is None:
                return _json(200, {"enabled": False, "models": []})
            models = reg.list_models()
            result = []
            for mid in models:
                versions = reg.list_versions(mid)
                result.append({
                    "model_id": mid,
                    "versions": [v.to_dict() for v in versions],
                })
            return _json(200, {"count": len(result), "models": result})

        def h_models_get(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            reg = getattr(pipeline, "model_registry", None)
            model_id = ctx["params"].get("model_id")
            if not model_id:
                raise _BadRequest("model_id required")
            if reg is None:
                return _json(200, {"enabled": False, "versions": []})
            versions = reg.list_versions(model_id)
            return _json(200, {"model_id": model_id, "versions": [v.to_dict() for v in versions]})

        def h_models_promote(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            reg = getattr(pipeline, "model_registry", None)
            if reg is None:
                raise _BadRequest("model registry not configured")
            body = ctx.get("body") or {}
            model_id = body.get("model_id")
            version = body.get("version")
            status_str = body.get("status", "production")
            if not model_id or version is None:
                raise _BadRequest("model_id and version required")
            from ..models.registry import ModelStatus
            try:
                to_status = ModelStatus(status_str)
            except ValueError:
                raise _BadRequest(f"unknown status: {status_str}")
            mv = reg.promote(model_id, int(version), to=to_status)
            if mv is None:
                return _json(404, {"error": "version not found"})
            return _json(200, mv.to_dict())

        def h_models_register(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            reg = getattr(pipeline, "model_registry", None)
            if reg is None:
                raise _BadRequest("model registry not configured")
            body = ctx.get("body") or {}
            model_id = body.get("model_id")
            detector_type = body.get("detector_type", "unknown")
            if not model_id:
                raise _BadRequest("model_id required")
            mv = reg.register(
                model_id,
                detector_type,
                train_samples=body.get("train_samples", 0),
                hyperparams=body.get("hyperparams", {}),
                tags=body.get("tags", []),
                notes=body.get("notes", ""),
            )
            return _json(201, mv.to_dict())

        def h_models_drift(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            trainers = getattr(pipeline, "_auto_trainers", {}) or {}
            model_id = ctx["params"].get("model_id")
            if model_id:
                trainer = trainers.get(model_id)
                if trainer is None:
                    return _json(200, {"enabled": False, "model_id": model_id})
                return _json(200, trainer.status())
            result = {mid: t.status() for mid, t in trainers.items()}
            return _json(200, {"count": len(result), "trainers": result})

        def h_models_train_history(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            trainers = getattr(pipeline, "_auto_trainers", {}) or {}
            model_id = ctx["params"].get("model_id")
            if not model_id:
                raise _BadRequest("model_id required")
            trainer = trainers.get(model_id)
            if trainer is None:
                return _json(200, {"enabled": False, "model_id": model_id, "events": []})
            return _json(200, {
                "model_id": model_id,
                "count": len(trainer.history()),
                "events": [e.to_dict() for e in trainer.history()],
            })

        def h_models_trigger_train(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            trainers = getattr(pipeline, "_auto_trainers", {}) or {}
            body = ctx.get("body") or {}
            model_id = body.get("model_id")
            if not model_id:
                raise _BadRequest("model_id required")
            trainer = trainers.get(model_id)
            if trainer is None:
                return _json(404, {"error": "trainer not found"})
            from ..models.trainer import TrainReason
            event = trainer.trigger(reason=TrainReason.MANUAL)
            return _json(200, event.to_dict())

        # reporting -------------------------------------------------
        def _report_store(self):
            return getattr(pipeline, "report_store", None)

        def _report_builder(self):
            return getattr(pipeline, "_report_builder", None)

        def _report_scheduler(self):
            return getattr(pipeline, "report_scheduler", None)

        def h_reports_list(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            store = self._report_store()
            if store is None:
                return _json(200, {"enabled": False, "reports": []})
            from ..reporting.model import ReportStatus, ReportType
            rtype = ctx["params"].get("type")
            rstatus = ctx["params"].get("status")
            limit = min(int((ctx["params"].get("limit", "50") or "50") or 50), 200)
            offset = int((ctx["params"].get("offset", "0") or "0") or 0)
            reports = store.list_reports(
                report_type=_enum_or_none(ReportType, rtype),
                status=_enum_or_none(ReportStatus, rstatus),
                limit=limit,
                offset=offset,
            )
            return _json(200, {
                "count": len(reports),
                "total": store.count(),
                "reports": [r.to_dict() for r in reports],
            })

        def h_reports_get(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            store = self._report_store()
            report_id = ctx["params"].get("id")
            if not report_id:
                raise _BadRequest("id required")
            if store is None:
                return _json(404, {"error": "report store not configured"})
            report = store.get(report_id)
            if report is None:
                return _json(404, {"error": "not found"})
            include_rendered = ctx["params"].get("rendered", "false").lower() == "true"
            return _json(200, report.to_dict(include_rendered=include_rendered))

        def h_reports_generate(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            builder = self._report_builder()
            store = self._report_store()
            if builder is None:
                raise _BadRequest("report builder not configured")
            body = ctx.get("body") or {}
            from ..reporting.model import ReportFormat, ReportType
            rtype = ReportType(body.get("report_type", "executive"))
            fmt = ReportFormat(body.get("format", "json"))
            lookback = float(body.get("lookback_s", 86_400.0))
            report = builder.build(
                report_type=rtype,
                format=fmt,
                lookback_s=lookback,
                title=body.get("title", ""),
                tags=body.get("tags", []),
            )
            from ..reporting.renderer import render_report
            report.rendered = render_report(report)
            if store is not None:
                store.save(report)
            return _json(201, report.to_dict(include_rendered=(fmt.value != "json")))

        def h_reports_stats(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            store = self._report_store()
            if store is None:
                return _json(200, {"enabled": False})
            return _json(200, {"enabled": True, **store.stats()})

        def h_schedules_list(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            scheduler = self._report_scheduler()
            if scheduler is None:
                return _json(200, {"enabled": False, "schedules": []})
            schedules = scheduler.list_schedules()
            return _json(200, {"count": len(schedules), "schedules": [s.to_dict() for s in schedules]})

        def h_schedules_create(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            scheduler = self._report_scheduler()
            if scheduler is None:
                raise _BadRequest("report scheduler not configured")
            body = ctx.get("body") or {}
            from ..reporting.model import ReportFormat, ReportSchedule, ReportType
            sch = ReportSchedule(
                name=body.get("name", ""),
                report_type=ReportType(body.get("report_type", "executive")),
                format=ReportFormat(body.get("format", "json")),
                interval_s=float(body.get("interval_s", 86_400.0)),
                lookback_s=float(body.get("lookback_s", 86_400.0)),
                tags=body.get("tags", []),
            )
            scheduler.add_schedule(sch)
            return _json(201, sch.to_dict())

        def h_schedules_delete(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            scheduler = self._report_scheduler()
            if scheduler is None:
                raise _BadRequest("report scheduler not configured")
            body = ctx.get("body") or {}
            schedule_id = body.get("schedule_id")
            if not schedule_id:
                raise _BadRequest("schedule_id required")
            removed = scheduler.remove_schedule(schedule_id)
            return _json(200, {"removed": removed})

        def h_schedules_run(self, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, str], bytes]:
            scheduler = self._report_scheduler()
            if scheduler is None:
                raise _BadRequest("report scheduler not configured")
            body = ctx.get("body") or {}
            schedule_id = body.get("schedule_id")
            if not schedule_id:
                raise _BadRequest("schedule_id required")
            report = scheduler.run_now(schedule_id)
            if report is None:
                return _json(404, {"error": "schedule not found"})
            return _json(200, report.to_dict())

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
        ("GET", "/forensics/stats"): _Handler.h_forensics_stats,
        ("GET", "/forensics/search"): _Handler.h_forensics_search,
        ("GET", "/forensics/histogram"): _Handler.h_forensics_histogram,
        ("GET", "/simulator/scenarios"): _Handler.h_sim_scenarios,
        ("POST", "/simulator/run"): _Handler.h_sim_run,
        ("GET", "/cases"): _Handler.h_cases_list,
        ("GET", "/cases/get"): _Handler.h_cases_get,
        ("POST", "/cases"): _Handler.h_cases_create,
        ("POST", "/cases/note"): _Handler.h_cases_note,
        ("GET", "/compliance/frameworks"): _Handler.h_compliance_frameworks,
        ("GET", "/compliance/report"): _Handler.h_compliance_report,
        # model registry
        ("GET", "/models"): _Handler.h_models_summary,
        ("GET", "/models/list"): _Handler.h_models_list,
        ("GET", "/models/get"): _Handler.h_models_get,
        ("POST", "/models/register"): _Handler.h_models_register,
        ("POST", "/models/promote"): _Handler.h_models_promote,
        ("GET", "/models/drift"): _Handler.h_models_drift,
        ("GET", "/models/train/history"): _Handler.h_models_train_history,
        ("POST", "/models/train/trigger"): _Handler.h_models_trigger_train,
        # reporting
        ("GET", "/reports"): _Handler.h_reports_list,
        ("GET", "/reports/get"): _Handler.h_reports_get,
        ("POST", "/reports/generate"): _Handler.h_reports_generate,
        ("GET", "/reports/stats"): _Handler.h_reports_stats,
        ("GET", "/reports/schedules"): _Handler.h_schedules_list,
        ("POST", "/reports/schedules"): _Handler.h_schedules_create,
        ("POST", "/reports/schedules/delete"): _Handler.h_schedules_delete,
        ("POST", "/reports/schedules/run"): _Handler.h_schedules_run,
        ("GET", "/"): _Handler.h_dashboard,
        ("GET", "/dashboard"): _Handler.h_dashboard,
    }
    return _Handler


def _forensics_store(pipeline):
    sink = getattr(pipeline, "forensics_sink", None)
    if sink is not None:
        return sink.store
    return getattr(pipeline, "forensics_store", None)


def _opt_float(value):
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _enum_or_none(enum_cls, value):
    if not value:
        return None
    try:
        return enum_cls(value)
    except ValueError:
        return None


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
