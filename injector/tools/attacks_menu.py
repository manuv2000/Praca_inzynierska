from injector.core.logging_setup import setup_logging
from injector.app.runner import run_scenario
from injector.app.scenario_loader import list_scenarios, build_scenario

import random
import time


def _ask_float(prompt: str, default: float) -> float:
    s = input(f"{prompt} [{default}]: ").strip()
    if not s:
        return float(default)
    try:
        return float(s.replace(",", "."))
    except ValueError:
        print("Invalid number, using default.")
        return float(default)


def _ask_int(prompt: str, default: int) -> int:
    s = input(f"{prompt} [{default}]: ").strip()
    if not s:
        return int(default)
    try:
        return int(s)
    except ValueError:
        print("Invalid int, using default.")
        return int(default)


def _ask_choice(prompt: str, options: dict, default_key: str):
    s = input(
        f"{prompt} ({', '.join([f'{k}={v}' for k, v in options.items()])}) [{default_key}]: "
    ).strip()
    if not s:
        s = default_key
    return options.get(s, options[default_key])


def main() -> None:
    setup_logging("INFO")

    scenarios = list_scenarios()
    if not scenarios:
        print("No scenarios found in config/scenarios.yaml")
        return

    print("=== PLC Security Simulation ===")
    for i, s in enumerate(scenarios, start=1):
        print(f"{i}) {s.get('id')} — {s.get('label', '')}")
    choice = input("Choose option: ").strip()

    try:
        idx = int(choice) - 1
        scenario_id = scenarios[idx].get("id")
    except Exception:
        print("Invalid choice")
        return

    # zaciągnij bazowe wartości tylko po to, żeby mieć defaulty do promptów
    _sid, _label, _cfg, _tasks, duration_s, seed, warmup_s, cooldown_s = build_scenario(str(scenario_id))

    print("\n--- Runtime overrides (ENTER = keep current) ---")
    duration_override = _ask_float("duration_s", float(duration_s or 60.0))
    warmup_override = _ask_float("warmup_s", float(warmup_s or 0.0))
    cooldown_override = _ask_float("cooldown_s", float(cooldown_s or 0.0))

    repeats = _ask_int("repeats", 1)

    seed_mode = _ask_choice(
        "seed mode",
        {"1": "yaml", "2": "random_per_run"},
        default_key="2",
    )

    for i in range(repeats):
        # WAŻNE: świeże cfg/tasks na każdy run
        scenario_id2, label, cfg, tasks, duration_s2, seed2, warmup_s2, cooldown_s2 = build_scenario(str(scenario_id))

        # wymuś runtime z override
        duration_s2 = duration_override
        warmup_s2 = warmup_override
        cooldown_s2 = cooldown_override

        run_seed = seed2
        if seed_mode == "random_per_run" or run_seed is None:
            run_seed = random.randint(1, 1_000_000)

        ts = time.strftime("%Y%m%d-%H%M%S")
        run_label = f"{scenario_id2}_run{i + 1}_seed{run_seed}_{ts}"

        run_scenario(
            scenario_id=scenario_id2,
            label=run_label,
            cfg=cfg,
            tasks=tasks,
            duration_s=duration_s2,
            seed=run_seed,
            warmup_s=warmup_s2,
            cooldown_s=cooldown_s2,
        )


if __name__ == "__main__":
    main()
