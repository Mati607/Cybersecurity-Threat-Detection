#!/usr/bin/env python3
"""Run threatpipe full-stack locally: pipeline + all subsystems + REST API + dashboard.

The bundled `threatpipe run` command only wires detection + alerts (+ triage
when enabled). This driver additionally wires the provenance graph, the
correlator + incident aggregator, the response engine, and the triage layer,
then starts the HTTP API so the dashboard at http://127.0.0.1:8088/ is fully
populated.

Pass scenario names to seed the dashboard with simulated attacks, e.g.:

    python run_fullstack.py                       # seed all scenarios
    python run_fullstack.py ransomware c2_beacon  # seed a subset
    python run_fullstack.py --none                # start empty, feed it yourself

Then browse http://127.0.0.1:8088/ or curl the API (see the printout).
Ctrl-C to stop.
"""

from __future__ import annotations

import signal
import sys
import time

from threatpipe.alerts import build_alert_sink
from threatpipe.api.server import ApiServer
from threatpipe.detection import DetectionPipeline
from threatpipe.graph import GraphBuilder, GraphCorrelator, ProvenanceGraph
from threatpipe.incidents import IncidentAggregator, IncidentStore
from threatpipe.response import ResponseEngine
from threatpipe.simulator import SimulationEngine, get_scenario, list_scenarios
from threatpipe.triage import PriorityScorer, SuppressionList, TriageEngine, TriageStore
from threatpipe.utils.config import PipelineConfig
from threatpipe.utils.logging_setup import configure_logging

HOST = "127.0.0.1"
PORT = 8088


def build_pipeline() -> DetectionPipeline:
    cfg = PipelineConfig()
    cfg.detection.engines = ["rule", "statistical", "isolation_forest"]
    cfg.api.host = HOST
    cfg.api.port = PORT
    cfg.triage.enabled = True

    pipeline = DetectionPipeline(cfg, alert_sink=build_alert_sink(cfg.alerts))

    # provenance graph + correlation + incidents
    graph = ProvenanceGraph()
    pipeline.graph = graph
    pipeline._graph_builder = GraphBuilder(graph)
    pipeline.correlator = GraphCorrelator(graph)
    pipeline.incident_aggregator = IncidentAggregator(IncidentStore())

    # automated response (dry-run so nothing touches the host)
    pipeline.response_engine = ResponseEngine(global_dry_run=True)

    # alert triage (dedup / suppression / priority)
    pipeline.triage_engine = TriageEngine(
        store=TriageStore(),
        suppressions=SuppressionList(),
        scorer=PriorityScorer(),
        dedup_window_s=cfg.triage.dedup_window_s,
    )
    return pipeline


def seed(pipeline: DetectionPipeline, scenario_ids) -> None:
    sim = SimulationEngine(pipeline)
    for sid in scenario_ids:
        result = sim.run(get_scenario(sid), host="victim01", user="jdoe")
        detected = sum(1 for s in result.step_results if s.detected)
        print(f"  seeded {sid:<20} events={result.events_emitted} steps_detected={detected}")


def main() -> int:
    configure_logging(level="INFO")
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    no_seed = "--none" in sys.argv[1:]

    pipeline = build_pipeline()
    pipeline.start()

    server = ApiServer(pipeline)
    server.start()

    if not no_seed:
        scenarios = args or [s.scenario_id for s in list_scenarios()]
        print(f"seeding {len(scenarios)} scenario(s) through the full pipeline:")
        try:
            seed(pipeline, scenarios)
        except Exception as exc:  # keep the server up even if seeding fails
            print(f"  seeding failed ({exc}); server still running")

    base = f"http://{HOST}:{PORT}"
    print(
        f"\nthreatpipe full-stack is up.\n"
        f"  Dashboard : {base}/\n"
        f"  Status    : curl {base}/status\n"
        f"  Detections: curl {base}/detections\n"
        f"  Triage    : curl {base}/triage | python -m json.tool\n"
        f"  Incidents : curl {base}/incidents\n"
        f"  Graph     : curl {base}/graph/stats\n"
        f"\nPOST your own events:\n"
        f"  curl -XPOST {base}/events -H 'Content-Type: application/json' \\\n"
        f"    -d '{{\"event_type\":\"process\",\"host\":\"web01\",\"process\":\"powershell.exe\","
        f"\"command_line\":\"powershell -enc {'A' * 16}\",\"action\":\"exec\"}}'\n"
        f"\nCtrl-C to stop."
    )

    stop = {"flag": False}

    def _stop(_signum, _frame):
        stop["flag"] = True

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    try:
        while not stop["flag"]:
            time.sleep(0.5)
    finally:
        server.stop()
        pipeline.stop()
        print("\nstopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
