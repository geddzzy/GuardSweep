import sys

from config.config import parse_args


def test_parse_args_override_flags(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "guardsweep.py",
            "--monitor_dir",
            "C:/temp",
            "--auto_respond",
            "--enable_quarantine",
            "--suspicious_process_names",
            "cmd.exe",
            "powershell.exe",
        ],
    )

    args = parse_args()

    assert args.monitor_dir == "C:/temp"
    assert args.auto_respond is True
    assert args.enable_quarantine is True
    assert args.suspicious_process_names == ["cmd.exe", "powershell.exe"]
