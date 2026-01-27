from injector.core.logging_setup import setup_logging
from injector.app.runner import run_scenario
from injector.app.scenario_loader import list_scenarios, build_scenario


def main() -> None:
    setup_logging("INFO")

    scenarios = list_scenarios()
    if not scenarios:
        print("No scenarios found in config/scenarios.yaml")
        return

    print("=== PLC Security Simulation ===")
    for i, s in enumerate(scenarios, start=1):
        print(f"{i}) {s.get('id')} — {s.get('label','')}")
    choice = input("Choose option: ").strip()

    try:
        idx = int(choice) - 1
        scenario_id = scenarios[idx].get("id")
    except Exception:
        print("Invalid choice")
        return

    scenario_id, label, cfg, tasks, duration_s, seed, warmup_s, cooldown_s = build_scenario(str(scenario_id))

    run_scenario(
        scenario_id=scenario_id,
        label=label,
        cfg=cfg,
        tasks=tasks,
        duration_s=duration_s,
        seed=seed,
        warmup_s=warmup_s,
        cooldown_s=cooldown_s,
    )


if __name__ == "__main__":
    main()
