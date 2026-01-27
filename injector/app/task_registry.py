# injector/app/task_registry.py

import threading
from injector.app.runner import TaskSpec

from injector.traffic.hmi_master import run_hmi_loop
from injector.traffic.normal_client import run_normal_client
from injector.attacks.scan_readonly import run_scan_readonly
from injector.attacks.write_injection import run_write_injection
from injector.attacks.mass_overwrite import run_mass_overwrite_fc16
from injector.attacks.modbus_proxy_spoof import run_modbus_proxy

REGISTRY = {
    "HMI": run_hmi_loop,
    "NORMAL": run_normal_client,
    "SCAN_RO": run_scan_readonly,
    "WRITE_INJ": run_write_injection,
    "MASS_OVERWRITE_FC16": run_mass_overwrite_fc16,
    "PROXY_SPOOF": run_modbus_proxy,
}

def make_task(kind: str, params: dict, *, start_first: bool = False) -> TaskSpec:

    if kind not in REGISTRY:
        raise KeyError(f"Unknown task kind: {kind}. Available: {sorted(REGISTRY)}")
    target = REGISTRY[kind]

    if kind == "PROXY_SPOOF":
        ready = threading.Event()
        merged = dict(params)

        merged.setdefault("ready_event", ready)
        return TaskSpec(
            name="PROXY",
            target=target,
            kwargs=merged,
            start_first=True,
            ready_event=ready,
            ready_timeout_s=2.0,
        )

    return TaskSpec(
        name=kind,
        target=target,
        kwargs=params,
        start_first=start_first,
    )
