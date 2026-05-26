from threatpipe.utils.timeutil import parse_timestamp, to_epoch, format_iso


def test_to_epoch_seconds_passthrough():
    assert abs(to_epoch(1_700_000_000.0) - 1_700_000_000.0) < 1e-6


def test_to_epoch_milliseconds():
    assert abs(to_epoch(1_700_000_000_000) - 1_700_000_000) < 1e-3


def test_to_epoch_microseconds():
    assert abs(to_epoch(1_700_000_000_000_000) - 1_700_000_000) < 1e-3


def test_to_epoch_nanoseconds():
    assert abs(to_epoch(1_700_000_000_000_000_000) - 1_700_000_000) < 1e-3


def test_parse_iso_with_z():
    assert parse_timestamp("2024-01-02T03:04:05Z") > 0


def test_parse_iso_with_offset():
    assert parse_timestamp("2024-01-02T03:04:05+02:00") > 0


def test_parse_empty_falls_back_to_now():
    assert parse_timestamp("") > 0
    assert parse_timestamp(None) > 0


def test_parse_numeric_string():
    assert parse_timestamp("1700000000") > 0


def test_format_iso_round_trip():
    s = format_iso(1_700_000_000.0)
    assert s.endswith("Z")
    assert "2023" in s
