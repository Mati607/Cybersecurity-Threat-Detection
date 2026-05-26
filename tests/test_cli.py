import json
from pathlib import Path

from threatpipe.cli import main


def test_cli_rules_prints_catalog(capsys):
    rc = main(["rules"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "T1486.RANSOMWARE_EXT" in out


def test_cli_parse_emits_json(capsys):
    rc = main([
        "parse",
        '{"@timestamp":"2024-01-02T03:04:05Z","process":{"name":"curl","pid":1}}',
    ])
    out = capsys.readouterr().out
    assert rc == 0
    payload = json.loads(out)
    assert payload["process"] == "curl"
    assert payload["detected_format"] == "json"


def test_cli_replay(tmp_path: Path, capsys):
    p = tmp_path / "events.jsonl"
    p.write_text(json.dumps({
        "event_type": "process",
        "command_line": "powershell -enc " + "A" * 64,
        "host": "h0",
    }) + "\n")
    rc = main(["replay", str(p)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "HIGH" in out or "CRITICAL" in out


def test_cli_replay_json_mode(tmp_path: Path, capsys):
    p = tmp_path / "events.jsonl"
    p.write_text(json.dumps({
        "event_type": "file",
        "file_path": "x.locked",
        "action": "write",
    }) + "\n")
    rc = main(["replay", str(p), "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    payload = json.loads(out.strip().splitlines()[0])
    assert payload["severity"] == "critical"
