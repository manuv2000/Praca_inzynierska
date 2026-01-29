from fastapi import FastAPI, WebSocket
from pathlib import Path
import asyncio
import time
from detector.model.pipeline import DetectorPipeline
from detector.features.extractor import extract_features_from_pcap

app = FastAPI()
pipeline = DetectorPipeline(Path("detector/artifacts"))

latest = {"ts": None, "result": None}
subscribers = set()

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/latest")
def get_latest():
    return latest

@app.websocket("/ws/anomaly")
async def ws_anomaly(ws: WebSocket):
    await ws.accept()
    subscribers.add(ws)
    try:
        while True:
            await asyncio.sleep(1)  # keep alive
    finally:
        subscribers.remove(ws)

async def broadcast(msg: dict):
    dead = []
    for ws in list(subscribers):
        try:
            await ws.send_json(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        subscribers.discard(ws)

# Background task: watch capture directory and process new pcaps
@app.on_event("startup")
async def startup():
    asyncio.create_task(runtime_loop())

async def runtime_loop():
    capture_dir = Path("runtime_pcaps")  # tu będą 5s pliki z tshark
    seen = set()
    while True:
        for p in sorted(capture_dir.glob("capture_*.pcapng")):
            if p in seen:
                continue
            seen.add(p)

            feats = extract_features_from_pcap(p)
            result = pipeline.score(feats)

            event = {
                "ts": time.time(),
                "features": feats,
                "result": result,
            }
            latest["ts"] = event["ts"]
            latest["result"] = event["result"]
            await broadcast(event)

        await asyncio.sleep(0.2)
