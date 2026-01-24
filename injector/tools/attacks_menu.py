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

    label, cfg, tasks, duration_s, seed = build_scenario(str(scenario_id))
    run_scenario(label=label, cfg=cfg, tasks=tasks, duration_s=duration_s, seed=seed)


if __name__ == "__main__":
    main()
