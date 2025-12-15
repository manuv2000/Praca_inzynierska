from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List


class StartScenarioRequest(BaseModel):
    name: str  # "baseline" | "baseline_proxy_spoof" | ...
    # w przyszłości: parametry scenariuszy


class ScenarioStatus(BaseModel):
    running: bool
    scenario: Optional[str] = None
    started_at_epoch: Optional[float] = None
    pcap_path: Optional[str] = None
    capture_pid: Optional[int] = None
    from pydantic import Field
    details: Dict[str, Any] = Field(default_factory=dict)


class PcapInfo(BaseModel):
    name: str
    path: str
    size_bytes: int
    mtime_epoch: float


class QuickStatsResponse(BaseModel):
    ok: bool
    file: str
    path: str
    features: Dict[str, Any]
