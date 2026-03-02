import logging

from core.alerts import alert


def test_alert_maps_alert_alias_to_critical(monkeypatch):
    calls = []

    def fake_log(level, message):
        calls.append((level, message))

    monkeypatch.setattr(logging, "log", fake_log)
    alert("critical-path", severity="ALERT")

    assert calls == [(logging.CRITICAL, "critical-path")]


def test_alert_maps_unknown_to_info(monkeypatch):
    calls = []

    def fake_log(level, message):
        calls.append((level, message))

    monkeypatch.setattr(logging, "log", fake_log)
    alert("fallback", severity="UNKNOWN")

    assert calls == [(logging.INFO, "fallback")]
