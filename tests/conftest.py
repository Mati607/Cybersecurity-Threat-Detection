"""Shared test fixtures.

We seed Python's RNG so the ML detectors stay deterministic across
test runs, and we provide a couple of small event factories used by
multiple test modules.
"""

from __future__ import annotations

import random
from typing import Iterable, List

import pytest

from threatpipe.ingestion import Event, EventType


@pytest.fixture(autouse=True)
def _seed_rng():
    random.seed(7)
    yield


@pytest.fixture
def benign_events() -> List[Event]:
    rng = random.Random(0)
    out: List[Event] = []
    procs = ["bash", "sshd", "python", "curl", "grep", "ls", "cat"]
    cmds = [
        "python app.py", "ls -la", "grep foo bar.txt",
        "curl https://api.internal.example.com/health",
        "cat /etc/hosts", "sshd -D",
    ]
    for i in range(300):
        out.append(Event(
            timestamp=1_700_000_000 + i,
            event_type=EventType.PROCESS,
            host=f"host{i % 4}",
            user="alice",
            process=rng.choice(procs),
            pid=rng.randint(100, 9000),
            command_line=rng.choice(cmds),
            action="exec",
            source="test",
        ))
    return out


@pytest.fixture
def attack_event() -> Event:
    return Event(
        timestamp=1_700_001_000,
        event_type=EventType.PROCESS,
        host="host0",
        user="alice",
        process="powershell.exe",
        pid=1234,
        command_line="powershell -enc " + "A" * 64,
        action="exec",
        source="test",
    )


@pytest.fixture
def ransomware_event() -> Event:
    return Event(
        timestamp=1_700_002_000,
        event_type=EventType.FILE,
        host="host1",
        user="alice",
        file_path="C:/Users/alice/Documents/report.locked",
        action="write",
        source="test",
    )
