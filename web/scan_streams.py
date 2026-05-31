# Copyright 2026 Jayden Aung — Apache 2.0
"""
web/scan_streams.py — Thread-safe event queue registry for SSE scan feeds.

One queue per running scan. The background scan thread puts events; the SSE
endpoint drains them via asyncio.to_thread so the event loop is not blocked.
"""

import queue
from typing import Dict, Optional

_streams: Dict[int, queue.Queue] = {}


def create(scan_id: int) -> queue.Queue:
    q: queue.Queue = queue.Queue(maxsize=1000)
    _streams[scan_id] = q
    return q


def get(scan_id: int) -> Optional[queue.Queue]:
    return _streams.get(scan_id)


def remove(scan_id: int) -> None:
    _streams.pop(scan_id, None)
