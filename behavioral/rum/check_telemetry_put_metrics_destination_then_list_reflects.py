"""telemetry-put-metrics-destination-then-list-reflects."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "telemetry-put-metrics-destination-then-list-reflects"
GROUP = "telemetry"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutRumMetricsDestination is immediately visible in ListRumMetricsDestinations."""
    rum = ctx.client("rum")
    name = _create_app_monitor(ctx)

    rum.put_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    ctx.on_cleanup(
        lambda: rum.delete_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    )

    resp = rum.list_rum_metrics_destinations(AppMonitorName=name)
    destinations = resp["Destinations"]
    assert len(destinations) == 1, f"expected exactly one destination, got {destinations}"
    assert destinations[0]["Destination"] == "CloudWatch", (
        f"expected CloudWatch destination, got {destinations[0]}"
    )
    assert not destinations[0].get("DestinationArn"), (
        f"CloudWatch destination should carry no DestinationArn, got {destinations[0]}"
    )


def _create_app_monitor(ctx, domain: str = "example.com") -> str:
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-behav-rum-")
    rum.create_app_monitor(Name=name, Domain=domain, Tags={"Team": "rum-fidelity"})
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
