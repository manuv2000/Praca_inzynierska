import os
import uvicorn
from fastapi import FastAPI, HTTPException
from pathlib import Path
from typing import List
from fastapi.responses import Response

from injector.core.logging_setup import setup_logging
from analysis.quick_modbus_stats import extract_features  # wykorzystujemy Twoje aktualne
from capture.core.capture_control import PCAP_DIR  # u Ciebie to jest zmienna w module; jeśli nieexportowana, podmień na Path
from contextlib import asynccontextmanager

from api.runner import ScenarioRunner
from api.models import StartScenarioRequest, ScenarioStatus, PcapInfo, QuickStatsResponse
from api.pcap_export import pcap_to_json



runner = ScenarioRunner()

@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging("INFO")
    try:
        yield
    finally:
        # zawsze spróbuj zatrzymać scenariusz i capture
        try:
            runner.stop()
        except Exception:
            pass

app = FastAPI(
    title="PLC Runtime API",
    version="0.1",
    lifespan=lifespan
)



@app.get("/status", response_model=ScenarioStatus)
def status():
    return runner.status()

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/scenario/start", response_model=ScenarioStatus)
def start(req: StartScenarioRequest):
    try:
        return runner.start(req.name)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/scenario/stop", response_model=ScenarioStatus)
def stop():
    return runner.stop()


@app.get("/pcaps", response_model=List[PcapInfo])
def list_pcaps():
    pcap_dir = Path(PCAP_DIR)
    if not pcap_dir.exists():
        return []
    out = []
    for p in sorted(pcap_dir.iterdir(), key=lambda x: x.stat().st_mtime):
        if p.suffix.lower() in (".pcap", ".pcapng") and p.is_file():
            st = p.stat()
            out.append(PcapInfo(
                name=p.name,
                path=str(p),
                size_bytes=st.st_size,
                mtime_epoch=st.st_mtime,
            ))
    return out


@app.get("/pcaps/{pcap_name}/quick-stats", response_model=QuickStatsResponse)
def quick_stats(pcap_name: str):
    p = Path(PCAP_DIR) / pcap_name
    if not p.exists():
        raise HTTPException(status_code=404, detail="pcap not found")

    feats = extract_features(p)  # korzysta z Twojego decode-as/portów
    if not feats.get("ok", False):
        return QuickStatsResponse(ok=False, file=pcap_name, path=str(p), features=feats)

    return QuickStatsResponse(ok=True, file=pcap_name, path=str(p), features=feats)


@app.get("/pcaps/{pcap_name}/json")
def export_json(pcap_name: str):
    p = Path(PCAP_DIR) / pcap_name
    if not p.exists():
        raise HTTPException(status_code=404, detail="pcap not found")

    s = pcap_to_json(p)  # string z JSON
    return Response(content=s, media_type="application/json")

@app.post("/scenario/kill")
def kill():
    # 1) ustaw stop_event
    # 2) ubij capture proces (tshark/dumpcap) bez czekania
    return {"ok": True}



if __name__ == "__main__":
    # Windows-friendly
    uvicorn.run(app, host="127.0.0.1", port=8000)
