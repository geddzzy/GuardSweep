import json
from types import SimpleNamespace

from core.status import build_startup_status, write_startup_status


def _args() -> SimpleNamespace:
    return SimpleNamespace(
        monitor_dir="C:/temp",
        run_seconds=10,
        auto_respond=True,
        enable_quarantine=False,
        enable_network_blocking=True,
        suspicious_extensions=[".exe"],
        suspicious_process_names=["powershell.exe"],
        blacklisted_ips=["1.2.3.4"],
    )


def test_build_startup_status_fields() -> None:
    payload = build_startup_status(_args())
    assert payload["monitor_dir"] == "C:/temp"
    assert payload["run_seconds"] == 10
    assert payload["enable_network_blocking"] is True


def test_write_startup_status(tmp_path) -> None:
    target = tmp_path / "status.json"
    write_startup_status(str(target), _args())
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["auto_respond"] is True
    assert data["suspicious_process_names"] == ["powershell.exe"]
