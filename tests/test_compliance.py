import pytest

from threatpipe.compliance import (
    ControlMapper,
    Framework,
    analyze_gaps,
    build_compliance_report,
    get_framework,
    list_frameworks,
)
from threatpipe.detection import RuleEngine
from threatpipe.detection.rule_engine import Rule


def test_frameworks_loaded():
    ids = {f.framework_id for f in list_frameworks()}
    assert {"nist-800-53", "cis-v8", "pci-dss-v4", "iso-27001"} <= ids


def test_get_framework_unknown_raises():
    with pytest.raises(KeyError):
        get_framework("nope")


def test_framework_families_and_controls():
    fw = get_framework("nist-800-53")
    assert fw.control("SI-4") is not None
    assert "Access Control" in fw.families()


def test_mapper_covers_controls_from_default_rules():
    fw = get_framework("nist-800-53")
    mapper = ControlMapper(fw)
    mapper.add_rules(RuleEngine().rules)
    summary = mapper.summary()
    assert summary["controls_total"] == len(fw.controls)
    assert summary["controls_covered"] > 0


def test_mapper_subtechnique_rolls_up_to_parent():
    fw = get_framework("nist-800-53")
    mapper = ControlMapper(fw)
    # rule tagged with a sub-technique should satisfy a control that
    # references the parent technique (SI-3 references T1059)
    mapper.add_rules([Rule(id="X", name="x", tags=["mitre:T1059.001"])])
    coverage = {c.control_id: c for c in mapper.coverage()}
    assert coverage["SI-3"].covered


def test_uncovered_control_when_no_rules():
    fw = get_framework("nist-800-53")
    mapper = ControlMapper(fw)
    coverage = mapper.coverage()
    assert all(not c.covered for c in coverage)


def test_gap_analysis_lists_missing():
    fw = get_framework("pci-dss-v4")
    gaps = analyze_gaps(fw, [])
    assert len(gaps.uncovered_controls) == len(fw.controls)
    assert gaps.missing_techniques  # should rank techniques by unlock count


def test_gap_analysis_partial_coverage():
    fw = get_framework("nist-800-53")
    # cover only T1059 -> SI-3 (also needs T1027/T1486/T1620) is partial
    gaps = analyze_gaps(fw, [Rule(id="X", name="x", tags=["mitre:T1059"])])
    partial_ids = {p["control_id"] for p in gaps.partially_covered}
    assert "SI-3" in partial_ids


def test_compliance_report_shape():
    fw = get_framework("cis-v8")
    report = build_compliance_report(fw, RuleEngine().rules)
    assert report["framework"]["id"] == "cis-v8"
    assert "summary" in report and "gaps" in report
    assert report["posture"] in ("strong", "moderate", "developing", "initial")


def test_framework_from_dict_round_trip():
    fw = get_framework("iso-27001")
    fw2 = Framework.from_dict(fw.to_dict())
    assert fw2.framework_id == fw.framework_id
    assert len(fw2.controls) == len(fw.controls)
