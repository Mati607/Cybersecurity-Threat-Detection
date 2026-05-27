import json
from pathlib import Path

import pytest

from threatpipe.attck import (
    AttckCatalog,
    CoverageMap,
    SigmaConversionError,
    SigmaImporter,
    Tactic,
    sigma_to_rules,
    to_navigator_layer,
)
from threatpipe.detection import RuleEngine


# --- catalog -----------------------------------------------------

def test_catalog_default_techniques_loaded():
    cat = AttckCatalog()
    assert len(cat) > 30
    assert cat.get("T1059") is not None


def test_catalog_subtechnique_lookup_falls_back_to_parent():
    cat = AttckCatalog()
    assert cat.get("T1059.999").technique_id == "T1059"


def test_catalog_by_tactic_filters_correctly():
    cat = AttckCatalog()
    techs = cat.by_tactic(Tactic.EXECUTION)
    assert any(t.technique_id == "T1059" for t in techs)


def test_catalog_search():
    cat = AttckCatalog()
    hits = cat.search("powershell")
    assert any("PowerShell" in t.name for t in hits)


def test_catalog_to_from_dict_round_trip():
    cat = AttckCatalog()
    data = cat.to_dict()
    cat2 = AttckCatalog.from_dict(data)
    assert len(cat2) == len(cat)


# --- coverage ----------------------------------------------------

def test_coverage_against_default_rules():
    cov = CoverageMap()
    cov.add_rules(RuleEngine().rules)
    summary = cov.summary()
    assert summary["techniques_covered"] > 0
    assert summary["techniques_total"] > 0


def test_coverage_unknown_techniques_recorded():
    from threatpipe.detection.rule_engine import Rule
    cov = CoverageMap()
    cov.add_rules([Rule(id="X.1", name="x", tags=["mitre:T9999"])])
    summary = cov.summary()
    assert "T9999" in summary["unknown_techniques"]


def test_coverage_by_tactic_totals():
    cov = CoverageMap()
    cov.add_rules(RuleEngine().rules)
    by_tac = cov.by_tactic()
    assert "execution" in by_tac
    assert by_tac["execution"]["total"] > 0


# --- navigator layer ---------------------------------------------

def test_navigator_layer_shape():
    cov = CoverageMap()
    cov.add_rules(RuleEngine().rules)
    layer = to_navigator_layer(cov)
    assert layer["domain"] == "enterprise-attack"
    assert layer["techniques"]
    sample = layer["techniques"][0]
    assert "techniqueID" in sample and "color" in sample


# --- Sigma importer ----------------------------------------------

_BASIC_SIGMA = {
    "title": "PowerShell -enc",
    "id": "ps-enc",
    "level": "high",
    "tags": ["attack.t1059.001", "attack.execution"],
    "detection": {
        "selection": {
            "Image|endswith": ["powershell.exe", "pwsh.exe"],
            "CommandLine|contains": "-enc",
        },
        "condition": "selection",
    },
}


def test_sigma_to_rules_single_branch():
    rules = sigma_to_rules(_BASIC_SIGMA)
    assert len(rules) == 1
    r = rules[0]
    assert r.id == "SIGMA.ps-enc"
    assert "process" in r.where and "command_line" in r.where
    assert any("mitre:T1059.001" in t for t in r.tags)


def test_sigma_or_condition_produces_multiple_rules():
    doc = {
        "title": "Two-way OR",
        "id": "or-rule",
        "level": "medium",
        "detection": {
            "selection1": {"CommandLine|contains": "curl evil"},
            "selection2": {"CommandLine|contains": "wget bad"},
            "condition": "selection1 or selection2",
        },
    }
    rules = sigma_to_rules(doc)
    assert len(rules) == 2


def test_sigma_rejects_unsupported_operator():
    doc = {
        "title": "unsupported",
        "id": "u1",
        "detection": {
            "selection1": {"CommandLine": "x"},
            "condition": "not selection1",
        },
    }
    with pytest.raises(SigmaConversionError):
        sigma_to_rules(doc)


def test_sigma_importer_loads_yaml_file(tmp_path: Path):
    path = tmp_path / "rule.yml"
    path.write_text(
        "title: Some rule\n"
        "id: rule-yaml\n"
        "level: medium\n"
        "tags:\n"
        "  - attack.t1027\n"
        "detection:\n"
        "  selection:\n"
        "    CommandLine|contains: base64\n"
        "  condition: selection\n"
    )
    rules = SigmaImporter().load_file(path)
    assert len(rules) == 1
    assert rules[0].id == "SIGMA.rule-yaml"


def test_sigma_importer_load_dir_skips_invalid(tmp_path: Path):
    (tmp_path / "ok.yml").write_text(
        "title: ok\nid: ok\nlevel: low\ndetection:\n  selection:\n    CommandLine: foo\n  condition: selection\n"
    )
    (tmp_path / "bad.yml").write_text("title: bad\nid: bad\n")  # no detection
    imp = SigmaImporter()
    rules = imp.load_dir(tmp_path)
    assert [r.id for r in rules] == ["SIGMA.ok"]
    assert imp.errors
