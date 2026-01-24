# injector/modbus_proxy/state.py
from __future__ import annotations
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

@dataclass
class PendingReq:
    func: int
    start_addr: int
    count: int
    ts: float = field(default_factory=time.time)

@dataclass
class ConnState:
    """
    Per-connection state: map Transaction ID -> request metadata.
    """
    lock: threading.Lock = field(default_factory=threading.Lock)
    pending: Dict[int, PendingReq] = field(default_factory=dict)
    ttl_s: float = 5.0

    def put(self, tid: int, req: PendingReq) -> None:
        with self.lock:
            self.pending[tid] = req
            now = time.time()
            for k in list(self.pending.keys()):
                if now - self.pending[k].ts > self.ttl_s:
                    self.pending.pop(k, None)

    def pop(self, tid: int) -> Optional[PendingReq]:
        with self.lock:
            return self.pending.pop(tid, None)
