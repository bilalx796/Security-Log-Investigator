"""Loads security logs and normalizes them into a consistent internal format."""

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class Event:
    timestamp: datetime
    user: str
    event: str
    ip: Optional[str] = None
    device: Optional[str] = None


def normalize_event(raw: dict) -> Event:
    return Event(
        timestamp=datetime.fromisoformat(raw["timestamp"]),
        user=raw["user"],
        event=raw["event"],
        ip=raw.get("ip"),
        device=raw.get("device"),
    )


def load_logs(path: str) -> List[Event]:
    with open(path, "r") as f:
        raw_events = json.load(f)

    events = [normalize_event(raw) for raw in raw_events]
    events.sort(key=lambda e: e.timestamp)
    return events


def group_by_user(events: List[Event]) -> Dict[str, List[Event]]:
    grouped: Dict[str, List[Event]] = {}
    for event in events:
        grouped.setdefault(event.user, []).append(event)
    return grouped
