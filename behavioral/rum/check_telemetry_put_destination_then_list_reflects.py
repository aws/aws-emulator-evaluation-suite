"""telemetry-put-destination-then-list-reflects."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "telemetry-put-destination-then-list-reflects"
GROUP = "telemetry"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutRumMetricsDestination followed by ListRumMetricsDestinations returns the newly
    configured destination with matching attributes."""
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-behav-appmon-")
    rum.create_app_monitor(Name=name, Domain="example.com")
    ctx.on_cleanup(lambda: _safe_delete_app_monitor(ctx, name))

    rum.put_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    ctx.on_cleanup(
        lambda: rum.delete_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    )

    destinations = _poll_until(
        lambda: rum.list_rum_metrics_destinations(AppMonitorName=name)["Destinations"],
        lambda d: len(d) == 1,
        timeout_s=30.0,
    )
    assert destinations[0]["Destination"] == "CloudWatch", (
        f"expected Destination CloudWatch, got {destinations[0]!r}"
    )
    assert not destinations[0].get("DestinationArn"), "CloudWatch destination has no DestinationArn"


def _safe_delete_app_monitor(ctx, name: str) -> None:
    rum = ctx.client("rum")
    try:
        rum.delete_app_monitor(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
