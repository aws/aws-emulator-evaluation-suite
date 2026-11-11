"""telemetry-delete-metrics-destination-removes-from-list."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "telemetry-delete-metrics-destination-removes-from-list"
GROUP = "telemetry"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRumMetricsDestination removes the destination; a subsequent list omits it."""
    rum = ctx.client("rum")
    name = _create_app_monitor(ctx)

    rum.put_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    before = rum.list_rum_metrics_destinations(AppMonitorName=name)["Destinations"]
    assert len(before) == 1, f"expected the destination to be present first, got {before}"
    assert before[0]["Destination"] == "CloudWatch", (
        f"expected the registered destination to be CloudWatch, got {before[0]}"
    )

    rum.delete_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")

    after = rum.list_rum_metrics_destinations(AppMonitorName=name)["Destinations"]
    assert after == [], f"expected no destinations after delete, got {after}"


def _create_app_monitor(ctx, domain: str = "example.com") -> str:
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-behav-rum-")
    rum.create_app_monitor(Name=name, Domain=domain, Tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: _safe_delete_app_monitor(rum, name))
    return name


def _safe_delete_app_monitor(rum, name: str) -> None:
    try:
        rum.delete_app_monitor(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
