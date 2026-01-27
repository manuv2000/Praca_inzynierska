# injector/app/scenario_loader.py


from __future__ import annotations
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional

import yaml

from injector.core.config import PlcConfig, get_plc_config
from injector.app.task_registry import make_task
from injector.app.runner import TaskSpec


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_scenarios_yaml() -> Dict[str, Any]:
    path = _project_root() / "config" / "scenarios.yaml"
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError("scenarios.yaml must be a YAML mapping at top level")
    return data


def list_scenarios() -> List[Dict[str, Any]]:
    data = load_scenarios_yaml()
    scenarios = data.get("scenarios", []) or []
    if not isinstance(scenarios, list):
        raise ValueError("scenarios must be a list")
    return scenarios


def build_scenario(scenario_id: str, base_cfg: Optional[PlcConfig] = None) ->  Tuple[str, str, PlcConfig, List[TaskSpec], Optional[float], Optional[int], float, float]:

    data = load_scenarios_yaml()
    defaults = data.get("defaults", {}) or {}
    default_duration = defaults.get("duration_s", None)
    default_warmup = float(defaults.get("warmup_s", 0.0) or 0.0)
    default_cooldown = float(defaults.get("cooldown_s", 0.0) or 0.0)

    scenarios = data.get("scenarios", []) or []
    for s in scenarios:
        if s.get("id") == scenario_id:
            label = str(s.get("label", scenario_id))
            duration_s = s.get("duration_s", default_duration)
            warmup_s = float(s.get("warmup_s", default_warmup) or 0.0)
            cooldown_s = float(s.get("cooldown_s", default_cooldown) or 0.0)
            duration_s = float(duration_s) if duration_s is not None else None
            seed = s.get("seed", None)
            seed = int(seed) if seed is not None else None

            cfg = base_cfg or get_plc_config()

            # cfg_overrides
            overrides = s.get("cfg_overrides", {}) or {}
            if overrides:
                allowed = {f.name for f in cfg.__dataclass_fields__.values()}
                filtered = {k: v for k, v in overrides.items() if k in allowed}
                cfg = replace(cfg, **filtered)

            tasks_data = s.get("tasks", []) or []
            tasks: List[TaskSpec] = []
            for t in tasks_data:
                kind = str(t.get("kind"))
                params = t.get("params", {}) or {}
                start_first = bool(t.get("start_first", False))

                validate_task(kind, params)
                tasks.append(make_task(kind, params, start_first=start_first))

            return scenario_id, label, cfg, tasks, duration_s, seed, warmup_s, cooldown_s

    raise KeyError(f"Scenario not found: {scenario_id}")

def validate_task(kind: str, params: Dict[str, Any]) -> None:
    if not kind:
        raise ValueError("Task kind is empty")

    if kind == "WRITE_INJ":
        qps = float(params.get("qps", 0))
        if qps <= 0:
            raise ValueError("WRITE_INJ.qps must be > 0")

    if kind == "SCAN_RO":
        delay = float(params.get("delay_s", 0))
        if delay < 0:
            raise ValueError("SCAN_RO.delay_s must be >= 0")

    if kind == "MASS_OVERWRITE_FC16":
        workers = int(params.get("workers", 1))
        if workers <= 0:
            raise ValueError("MASS_OVERWRITE_FC16.workers must be >= 1")
        qpsw = float(params.get("qps_per_worker", 0))
        if qpsw <= 0:
            raise ValueError("MASS_OVERWRITE_FC16.qps_per_worker must be > 0")
