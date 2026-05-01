"""
Security dashboard data persistence helpers.
Stores runtime security status in data.txt at the project root.
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


DATA_FILE = _app_dir() / "data.txt"


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


SUSPICIOUS_THRESHOLD = 5.0   # attack% below this → "suspicious", not "attack"


def get_network_threat_level(data: Dict[str, Any]) -> str:
    """Return 'none' | 'suspicious' | 'attack', inferring from raw fields
    when network_threat_level hasn't been written yet (old data.txt)."""
    level = data.get("network_threat_level", "none")
    if level in ("suspicious", "attack"):
        return level
    # Backward-compat: old scans only set network_attacks_detected
    if data.get("network_attacks_detected", False):
        pct = float((data.get("last_scan_summary") or {}).get("attack_percentage", 0) or 0)
        return "suspicious" if pct < SUSPICIOUS_THRESHOLD else "attack"
    return "none"

def _default_data() -> Dict[str, Any]:
    return {
        "last_scan": None,
        "last_scan_type": None,
        "malware_detected": False,
        "network_attacks_detected": False,
        "network_threat_level": "none",   # "none" | "suspicious" | "attack"
        "real_time_monitoring": True,
        "firewall_integration": True,
        "threat_signatures_updated_at": _now_iso(),
        "quarantined_items": 0,
        "events": [],
    }


def ensure_data_file() -> None:
    if DATA_FILE.exists():
        return

    default_data = _default_data()
    DATA_FILE.write_text(json.dumps(default_data, indent=2), encoding="utf-8")


def load_security_data() -> Dict[str, Any]:
    ensure_data_file()

    try:
        data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        data = _default_data()
        save_security_data(data)
        return data

    # Keep schema stable if keys are missing.
    defaults = _default_data()
    for key, default_value in defaults.items():
        if key not in data:
            data[key] = default_value

    if not isinstance(data.get("events"), list):
        data["events"] = []

    return data


def save_security_data(data: Dict[str, Any]) -> None:
    DATA_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


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
    events.insert(
        0,
        {
            "title": title,
            "detail": detail,
            "timestamp": _now_iso(),
        },
    )

    # Keep only the newest 20 entries.
    data["events"] = events[:20]


def record_scan(scan_type: str, source: str) -> None:
    data = load_security_data()
    now = _now_iso()

    data["last_scan"] = now
    data["last_scan_type"] = scan_type
    _append_event(data, f"{scan_type} completed", f"Triggered from {source}")

    save_security_data(data)


def record_model_run(model_name: str, source: str) -> None:
    data = load_security_data()
    _append_event(data, f"{model_name} executed", f"Triggered from {source}")
    save_security_data(data)


# ── NEW: ML scan integration ──────────────────────────────────────────────────

def record_ml_scan_result(
    scan_type: str,
    attacks_detected: bool,
    ml_events: List[Dict[str, Any]],
    summary: Dict[str, Any],
) -> None:
    """
    Called by ml_classifier.py (and network_page.py) after an ML scan finishes.

    Parameters
    ----------
    scan_type       : "Quick Scan" or "Deep Scan"
    attacks_detected: True if any attack-class rows were found
    ml_events       : list of per-row attack dicts from the classifier
    summary         : aggregate stats dict from run_scan()
    """
    data = load_security_data()
    now  = _now_iso()

    pct = float(summary.get("attack_percentage", 0) or 0)
    if not attacks_detected:
        threat_level = "none"
    elif pct < SUSPICIOUS_THRESHOLD:
        threat_level = "suspicious"
    else:
        threat_level = "attack"

    data["last_scan"]                 = now
    data["last_scan_type"]            = scan_type
    data["network_attacks_detected"]  = threat_level == "attack"
    data["network_threat_level"]      = threat_level
    data["last_scan_summary"]         = summary

    # Build human-readable events for the GUI event feed
    n = summary.get("attacks_detected", len(ml_events))
    if threat_level == "attack":
        _append_event(
            data,
            f"{scan_type} — {n} threat(s) detected",
            f"{pct:.1f}% of {summary.get('total_rows', '?')} rows flagged as malicious",
        )
        high = [e for e in ml_events if e.get("severity") == "high"][:10]
        for evt in high:
            _append_event(
                data,
                f"Attack detected [{evt.get('protocol', '?')}]",
                f"src={evt.get('source_ip', '?')}  dst={evt.get('dest_ip', '?')}  "
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

    save_security_data(data)

def record_malware_scan_result(
    scan_type: str,
    infected: bool,
    total_files: int,
    clean_files: int,
    infected_files: int,
    quarantined_paths: list,
    elapsed_seconds: float,
) -> None:
    """
    Persist the result of a malware scan into data.txt.

    Parameters
    ----------
    scan_type         : "Signature Scan" or "Full Scan"
    infected          : True if any threats were found
    total_files       : total files scanned
    clean_files       : files that passed all checks
    infected_files    : files flagged and quarantined
    quarantined_paths : list of new quarantine file paths
    elapsed_seconds   : wall-clock duration of the scan
    """
    data = load_security_data()
    now  = _now_iso()

    data["last_scan"]        = now
    data["last_scan_type"]   = scan_type
    data["malware_detected"] = infected
    data["quarantined_items"] = data.get("quarantined_items", 0) + infected_files

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

    save_security_data(data)
