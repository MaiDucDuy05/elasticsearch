# validator.py
from datetime import datetime

REQUIRED_ZEEK = ["@timestamp", "source.ip", "destination.ip",
                 "network.transport"]
REQUIRED_SNORT = ["@timestamp", "source.ip", "destination.ip",
                  "rule.id", "event.severity"]

def _check_timestamp(doc: dict) -> bool:
    ts = doc.get("@timestamp", "")
    try:
        datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return True
    except (ValueError, AttributeError):
        return False

def validate_zeek(doc: dict) -> tuple[bool, str]:
    for field in REQUIRED_ZEEK:
        if field not in doc:
            return False, f"Missing required field: {field}"
    if not _check_timestamp(doc):
        return False, f"Bad @timestamp: {doc.get('@timestamp')}"
    if not isinstance(doc.get("source.port", 0), int):
        return False, "source.port must be int"
    return True, ""

def validate_snort(doc: dict) -> tuple[bool, str]:
    for field in REQUIRED_SNORT:
        if field not in doc:
            return False, f"Missing required field: {field}"
    if not _check_timestamp(doc):
        return False, f"Bad @timestamp: {doc.get('@timestamp')}"
    if not isinstance(doc.get("event.severity", 0), int):
        return False, "event.severity must be int"
    return True, ""