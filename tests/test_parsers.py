import json

from threatpipe.ingestion import (
    Event,
    EventType,
    Normalizer,
    detect_format,
    parse_line,
)


def test_detect_format_json():
    assert detect_format('{"a": 1}') == "json"


def test_detect_format_syslog():
    assert detect_format("<34>Oct 11 22:14:15 mymachine sshd[1234]: msg") == "syslog"


def test_detect_format_auditd():
    line = "type=SYSCALL msg=audit(1700000000.123:1): pid=1"
    assert detect_format(line) == "auditd"


def test_detect_format_cef():
    assert detect_format("CEF:0|Vendor|Product|1.0|100|Login|7|src=1.2.3.4") == "cef"


def test_detect_format_unknown():
    assert detect_format("not a real line") == "unknown"


def test_json_parser_ecs_aliases():
    ev = parse_line(json.dumps({
        "@timestamp": "2024-01-02T03:04:05Z",
        "event": {"category": "process", "action": "exec"},
        "process": {"name": "/usr/bin/curl", "pid": 12, "command_line": "curl evil"},
        "user.name": "ROOT",
    }))
    assert ev is not None
    n = Normalizer()(ev)
    assert n.event_type == EventType.PROCESS
    assert n.action == "exec"
    assert n.process == "curl"            # Normalizer trims the path
    assert n.user == "root"
    assert n.command_line == "curl evil"
    assert n.pid == 12


def test_syslog_parser_extracts_pid_and_host():
    ev = parse_line("<34>Oct 11 22:14:15 mybox sshd[42]: failed password for root")
    assert ev is not None
    assert ev.host == "mybox"
    assert ev.process == "sshd"
    assert ev.pid == 42
    assert "failed password" in ev.message.lower()


def test_auditd_parser_kv_fields():
    ev = parse_line(
        'type=SYSCALL msg=audit(1700000000.500:7): arch=c000003e syscall=59 success=yes '
        'exit=0 pid=99 ppid=1 comm="bash" exe="/bin/bash" key="exec"'
    )
    assert ev is not None
    assert ev.event_type == EventType.SYSCALL
    assert ev.process == "bash"
    assert ev.pid == 99
    assert ev.parent_pid == 1


def test_cef_parser_network_fields():
    ev = parse_line("CEF:0|Vendor|Product|1.0|100|Login Failed|7|src=10.0.0.1 dst=10.0.0.2 spt=1234 dpt=22 suser=alice")
    assert ev is not None
    assert ev.event_type == EventType.NETWORK
    assert ev.src_ip == "10.0.0.1"
    assert ev.dst_ip == "10.0.0.2"
    assert ev.dst_port == 22
    assert ev.user == "alice"


def test_invalid_json_falls_through_to_raw():
    ev = parse_line("{not really json}")
    # The format sniffer thinks it's json (starts with '{' ends with '}'),
    # the JSON parser returns None, and the dispatcher refuses to invent.
    assert ev is None


def test_empty_line_returns_none():
    assert parse_line("") is None
    assert parse_line("   \n") is None
