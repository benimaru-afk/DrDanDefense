"""
Security dashboard data persistence helpers.

Data is stored in two separate files at the project root:
  - network_data.txt  — network scan results & events
  - malware_data.txt  — malware scan results & events

The dashboard page reads from both to show a combined view.
"""

from __future__ import annotations

from datetime import datetime, timedelta
import json
import sys
from pathlib import Path
from typing import Any, Dict, List


def _app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


NETWORK_DATA_FILE = _app_dir() / "network_data.txt"
MALWARE_DATA_FILE = _app_dir() / "malware_data.txt"

# Keep a legacy alias so any code that still imports DATA_FILE doesn't crash
DATA_FILE = NETWORK_DATA_FILE


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


SUSPICIOUS_THRESHOLD = 5.0   # attack% below this → "suspicious", not "attack"


def get_network_threat_level(data: Dict[str, Any]) -> str:
    """Return 'none' | 'suspicious' | 'attack'."""
    level = data.get("network_threat_level", "none")
    if level in ("suspicious", "attack"):
        return level
    if data.get("network_attacks_detected", False):
        pct = float((data.get("last_scan_summary") or {}).get("attack_percentage", 0) or 0)
        return "suspicious" if pct < SUSPICIOUS_THRESHOLD else "attack"
    return "none"


# ── Default schemas ────────────────────────────────────────────────────────────

def _default_network_data() -> Dict[str, Any]:
    return {
        "last_scan": None,
        "last_scan_type": None,
        "network_attacks_detected": False,
        "network_threat_level": "none",
        "real_time_monitoring": True,
        "firewall_integration": True,
        "threat_signatures_updated_at": _now_iso(),
        "last_scan_summary": {},
        "events": [],
    }


def _default_malware_data() -> Dict[str, Any]:
    return {
        "last_scan": None,
        "last_scan_type": None,
        "malware_detected": False,
        "quarantined_items": 0,
        "last_scan_summary": {},
        "events": [],
    }


# ── Generic file helpers ───────────────────────────────────────────────────────

def _ensure_file(path: Path, default_fn) -> None:
    if not path.exists():
        path.write_text(json.dumps(default_fn(), indent=2), encoding="utf-8")


def _load_file(path: Path, default_fn) -> Dict[str, Any]:
    _ensure_file(path, default_fn)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        data = default_fn()
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return data

    defaults = default_fn()
    for key, val in defaults.items():
        if key not in data:
            data[key] = val

    if not isinstance(data.get("events"), list):
        data["events"] = []

    return data


def _save_file(path: Path, data: Dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ── Public loaders / savers ───────────────────────────────────────────────────

def load_network_data() -> Dict[str, Any]:
    return _load_file(NETWORK_DATA_FILE, _default_network_data)


def save_network_data(data: Dict[str, Any]) -> None:
    _save_file(NETWORK_DATA_FILE, data)


def load_malware_data() -> Dict[str, Any]:
    return _load_file(MALWARE_DATA_FILE, _default_malware_data)


def save_malware_data(data: Dict[str, Any]) -> None:
    _save_file(MALWARE_DATA_FILE, data)


# Legacy shim — existing code that calls load_security_data() / save_security_data()
# will get the network data store (the only caller was network_page).
def load_security_data() -> Dict[str, Any]:
    return load_network_data()


def save_security_data(data: Dict[str, Any]) -> None:
    save_network_data(data)


# ── Formatting helpers ────────────────────────────────────────────────────────

def format_timestamp(value: Any) -> str:
    if not value:
        return "N/A"
    if isinstance(value, datetime):
        return value.strftime("%b %d, %Y %I:%M %p")
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
            return parsed.strftime("%b %d, %Y %I:%M %p")
        except ValueError:
            return "N/A"
    return "N/A"


def next_scheduled_scan(last_scan_value: Any) -> str:
    if not last_scan_value or not isinstance(last_scan_value, str):
        return "N/A"
    try:
        next_time = datetime.fromisoformat(last_scan_value) + timedelta(days=1)
    except ValueError:
        return "N/A"
    return next_time.strftime("%b %d, %Y %I:%M %p")


def _append_event(data: Dict[str, Any], title: str, detail: str) -> None:
    events: List[Dict[str, str]] = data.get("events", [])
    events.insert(0, {"title": title, "detail": detail, "timestamp": _now_iso()})
    data["events"] = events[:20]


# ── Network scan persistence ──────────────────────────────────────────────────

def record_ml_scan_result(
    scan_type: str,
    attacks_detected: bool,
    ml_events: List[Dict[str, Any]],
    summary: Dict[str, Any],
) -> None:
    """Called by ml_classifier.py after an ML scan finishes."""
    data = load_network_data()
    now  = _now_iso()

    pct = float(summary.get("attack_percentage", 0) or 0)
    if not attacks_detected:
        threat_level = "none"
    elif pct < SUSPICIOUS_THRESHOLD:
        threat_level = "suspicious"
    else:
        threat_level = "attack"

    data["last_scan"]               = now
    data["last_scan_type"]          = scan_type
    data["network_attacks_detected"] = threat_level == "attack"
    data["network_threat_level"]    = threat_level
    data["last_scan_summary"]       = summary

    n = summary.get("attacks_detected", len(ml_events))
    if threat_level == "attack":
        _append_event(
            data,
            f"{scan_type} — {n} threat(s) detected",
            f"{pct:.1f}% of {summary.get('total_rows', '?')} rows flagged as malicious",
        )
        for evt in [e for e in ml_events if e.get("severity") == "high"][:10]:
            _append_event(
                data,
                f"Attack detected [{evt.get('protocol', '?')}]",
                f"confidence={evt.get('confidence', 0):.0%}",
            )
    elif threat_level == "suspicious":
        _append_event(
            data,
            f"{scan_type} — Suspicious traffic detected",
            f"{pct:.1f}% of {summary.get('total_rows', '?')} rows flagged "
            f"(below {SUSPICIOUS_THRESHOLD:.0f}% attack threshold)",
        )
    else:
        _append_event(
            data,
            f"{scan_type} — No threats detected",
            f"All {summary.get('total_rows', '?')} rows classified as normal",
        )

    save_network_data(data)


# ── Malware scan persistence ──────────────────────────────────────────────────

def record_malware_scan_result(
    scan_type: str,
    infected: bool,
    total_files: int,
    clean_files: int,
    infected_files: int,
    quarantined_paths: list,
    elapsed_seconds: float,
) -> None:
    """Persist the result of a malware scan into malware_data.txt."""
    data = load_malware_data()
    now  = _now_iso()

    data["last_scan"]        = now
    data["last_scan_type"]   = scan_type
    data["malware_detected"] = infected
    data["quarantined_items"] = data.get("quarantined_items", 0) + infected_files
    data["last_scan_summary"] = {
        "total_files":      total_files,
        "clean_files":      clean_files,
        "infected_files":   infected_files,
        "elapsed_seconds":  elapsed_seconds,
        "attack_percentage": round(infected_files / total_files * 100, 2) if total_files else 0,
    }

    if infected:
        _append_event(
            data,
            f"{scan_type} — {infected_files} threat(s) found",
            f"{infected_files}/{total_files} file(s) flagged as malicious",
        )
        for qpath in quarantined_paths[:10]:
            _append_event(data, "File quarantined", Path(qpath).name)
    else:
        _append_event(
            data,
            f"{scan_type} — No threats found",
            f"All {total_files} file(s) clean",
        )

    save_malware_data(data)


# ── Legacy no-op helpers (called by old code paths) ──────────────────────────

def record_scan(scan_type: str, source: str) -> None:
    data = load_network_data()
    data["last_scan"] = _now_iso()
    data["last_scan_type"] = scan_type
    _append_event(data, f"{scan_type} completed", f"Triggered from {source}")
    save_network_data(data)

def record_model_run(model_name: str, source: str) -> None:
    data = load_network_data()
    _append_event(data, f"{model_name} executed", f"Triggered from {source}")
    save_network_data(data)