"""delete-rum-metrics-destination-unknown-conflict."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "delete-rum-metrics-destination-unknown-conflict"
GROUP = "error-semantics"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRumMetricsDestination for a destination never configured succeeds as a no-op and none
    is listed; once a destination is configured, deleting it removes it from the list.
    """
    rum = ctx.client("rum")
    app = _create_app_monitor(ctx)

    initial = rum.list_rum_metrics_destinations(AppMonitorName=app["name"])
    assert initial["Destinations"] == [], (
        f"expected a fresh app monitor to have no metrics destinations, got {initial['Destinations']}"
    )

    # Break exactly one thing: delete a CloudWatch destination that was never put.
    # AWS accepts this as a no-op (HTTP 200, no error) rather than
    # rejecting it -- unlike DeleteResourcePolicy, which does reject an absent policy.
    # The call must succeed: any ClientError propagates and fails the check.
    rum.delete_rum_metrics_destination(AppMonitorName=app["name"], Destination="CloudWatch")

    # Effect absent: still nothing configured.
    after_noop = rum.list_rum_metrics_destinations(AppMonitorName=app["name"])
    assert after_noop["Destinations"] == [], (
        f"expected the no-op delete to leave the destination list empty, got {after_noop['Destinations']}"
    )

    # Positive control (same file): configure the destination for real, then delete it.
    rum.put_rum_metrics_destination(AppMonitorName=app["name"], Destination="CloudWatch")
    configured = rum.list_rum_metrics_destinations(AppMonitorName=app["name"])
    assert any(d["Destination"] == "CloudWatch" for d in configured["Destinations"]), (
        f"expected CloudWatch to be configured, got {configured['Destinations']}"
    )

    rum.delete_rum_metrics_destination(AppMonitorName=app["name"], Destination="CloudWatch")
    final = rum.list_rum_metrics_destinations(AppMonitorName=app["name"])
    assert not any(d["Destination"] == "CloudWatch" for d in final["Destinations"]), (
        f"expected CloudWatch to be gone after delete, got {final['Destinations']}"
    )

    # Deleting it a second time (now absent again) is also a no-op, confirming
    # idempotency rather than a one-shot allowance.
    rum.delete_rum_metrics_destination(AppMonitorName=app["name"], Destination="CloudWatch")

    # Terminal assertion: an independent read at the destination, not the mutating
    # delete call's own (already-checked) outcome.
    still_empty = rum.list_rum_metrics_destinations(AppMonitorName=app["name"])
    assert still_empty["Destinations"] == [], (
        f"expected the list to still be empty after the second no-op delete, "
        f"got {still_empty['Destinations']}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _app_monitor_arn(ctx, name):
    return f"arn:aws:rum:{ctx.region}:{_account_id(ctx)}:appmonitor/{name}"


def _create_app_monitor(ctx, name=None, **kwargs):
    rum = ctx.client("rum")
    name = name or ctx.unique_name("sim2real-rum-am-")
    kwargs.setdefault("Domain", "example.com")
    resp = rum.create_app_monitor(Name=name, **kwargs)

    def _cleanup():
        try:
            rum.delete_app_monitor(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return {"name": name, "id": resp["Id"], "arn": _app_monitor_arn(ctx, name)}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
