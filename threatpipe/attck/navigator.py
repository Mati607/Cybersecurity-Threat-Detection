"""Export a :class:`~threatpipe.attck.CoverageMap` as an ATT&CK Navigator layer.

The Navigator layer format is a small JSON document the public web
viewer at https://mitre-attack.github.io/attack-navigator/ can render
directly. Color is bucketed by rule count so the map highlights
under-served techniques at a glance.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from .coverage import CoverageMap


_GRADIENT_COLORS = ["#f7f7f7", "#fdd49e", "#fdae6b", "#fd8d3c", "#e6550d", "#a63603"]


def _color_for(rule_count: int) -> str:
    idx = min(len(_GRADIENT_COLORS) - 1, rule_count)
    return _GRADIENT_COLORS[idx]


def to_navigator_layer(
    coverage: CoverageMap,
    *,
    name: str = "threatpipe coverage",
    description: str = "Detection rules mapped to MITRE ATT&CK",
    domain: str = "enterprise-attack",
) -> Dict[str, Any]:
    techniques: List[Dict[str, Any]] = []
    for entry in coverage.coverage():
        comment_parts = [f"{entry.rule_count} rules"]
        if entry.rule_ids:
            comment_parts.append("ids: " + ", ".join(sorted(set(entry.rule_ids))[:8]))
        if entry.severities:
            comment_parts.append("severities: " + ", ".join(sorted(set(entry.severities))))
        techniques.append({
            "techniqueID": entry.technique_id,
            "score": entry.rule_count,
            "color": _color_for(entry.rule_count),
            "comment": " | ".join(comment_parts),
            "enabled": True,
            "metadata": [
                {"name": "rule_count", "value": str(entry.rule_count)},
            ],
        })

    summary = coverage.summary()
    return {
        "name": name,
        "versions": {
            "attack": "14",
            "navigator": "4.9.0",
            "layer": "4.5",
        },
        "domain": domain,
        "description": description,
        "techniques": techniques,
        "gradient": {
            "colors": _GRADIENT_COLORS,
            "minValue": 0,
            "maxValue": max(1, max((t["score"] for t in techniques), default=1)),
        },
        "legendItems": [
            {"label": "0 rules", "color": _GRADIENT_COLORS[0]},
            {"label": "1 rule",  "color": _GRADIENT_COLORS[1]},
            {"label": "2-3 rules", "color": _GRADIENT_COLORS[2]},
            {"label": "4+ rules",  "color": _GRADIENT_COLORS[4]},
        ],
        "metadata": [
            {"name": "techniques_total",    "value": str(summary["techniques_total"])},
            {"name": "techniques_covered",  "value": str(summary["techniques_covered"])},
        ],
    }
