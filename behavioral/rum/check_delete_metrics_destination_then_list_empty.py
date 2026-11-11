"""delete-metrics-destination-then-list-empty."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "delete-metrics-destination-then-list-empty"
GROUP = "telemetry"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRumMetricsDestination removes the destination such that
    ListRumMetricsDestinations no longer returns it.
    """
    rum = ctx.client("rum")
    app_name = _create_app_monitor(ctx)

    rum.put_rum_metrics_destination(AppMonitorName=app_name, Destination="CloudWatch")
    listed_before = rum.list_rum_metrics_destinations(AppMonitorName=app_name)
    assert len(listed_before["Destinations"]) == 1, (
        f"destination did not register, got {listed_before['Destinations']}"
    )
    assert listed_before["Destinations"][0]["Destination"] == "CloudWatch", (
        f"expected the registered destination to be CloudWatch, got {listed_before['Destinations'][0]}"
    )

    rum.delete_rum_metrics_destination(AppMonitorName=app_name, Destination="CloudWatch")

    listed_after = rum.list_rum_metrics_destinations(AppMonitorName=app_name)
    assert listed_after["Destinations"] == [], (
        f"expected no destinations after delete, got {listed_after['Destinations']}"
    )


def _create_app_monitor(ctx: Any) -> str:
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-app-")
    rum.create_app_monitor(
        Name=name,
        Domain="sim2real.example.com",
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-rum-app-"},
    )
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
