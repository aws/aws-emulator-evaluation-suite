"""telemetry-delete-destination-removes-from-list."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "telemetry-delete-destination-removes-from-list"
GROUP = "telemetry"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRumMetricsDestination removes the destination such that a subsequent
    ListRumMetricsDestinations no longer includes it."""
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-behav-appmon-")
    rum.create_app_monitor(
        Name=name,
        Domain="example.com",
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: _safe_delete_app_monitor(ctx, name))

    rum.put_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    _poll_until(
        lambda: rum.list_rum_metrics_destinations(AppMonitorName=name)["Destinations"],
        lambda d: len(d) == 1,
        timeout_s=30.0,
    )

    rum.delete_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")

    remaining = _poll_until(
        lambda: rum.list_rum_metrics_destinations(AppMonitorName=name)["Destinations"],
        lambda d: len(d) == 0,
        timeout_s=30.0,
    )
    assert remaining == [], f"expected no destinations after delete, got {remaining!r}"


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
