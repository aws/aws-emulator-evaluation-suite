"""alarm-delete-rejected-when-referenced-by-composite."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "alarm-delete-rejected-when-referenced-by-composite"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAlarms on a metric alarm a composite's AlarmRule references fails with ValidationError
    "Cannot delete <name> as there are composite alarm(s) depending on it." and the alarm stays;
    after the composite is deleted, the same call deletes it."""
    cw = ctx.client("cloudwatch")
    child = ctx.unique_name("sim2real-behav-child-")
    composite = ctx.unique_name("sim2real-behav-composite-")

    cw.put_metric_alarm(
        AlarmName=child,
        MetricName="Sim2RealMetric",
        Namespace="Sim2RealBehavioral",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
    )
    child_deleted = {"done": False}
    ctx.on_cleanup(lambda: None if child_deleted["done"] else cw.delete_alarms(AlarmNames=[child]))

    cw.put_composite_alarm(
        AlarmName=composite,
        AlarmRule=f'ALARM("{child}")',
        ActionsEnabled=False,
    )
    composite_deleted = {"done": False}
    ctx.on_cleanup(
        lambda: None if composite_deleted["done"] else cw.delete_alarms(AlarmNames=[composite])
    )

    # Give the composite alarm's dependency edge on `child` time to become visible via
    # DescribeAlarms before relying on it to reject the child's deletion.
    registered = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[composite], AlarmTypes=["CompositeAlarm"]).get(
            "CompositeAlarms", []
        ),
        lambda alarms: bool(alarms) and alarms[0].get("AlarmRule") == f'ALARM("{child}")',
        timeout_s=30.0,
    )
    assert registered, "composite alarm never became visible/registered via DescribeAlarms"

    # Break exactly one thing: the live composite-alarm reference. Real CloudWatch surfaces
    # this rejection as a generic ValidationError, not a dedicated ResourceConflict-style code.
    code, message = _error(lambda: cw.delete_alarms(AlarmNames=[child]))
    assert code == "ValidationError", f"expected ValidationError deleting referenced alarm, got {code}: {message}"
    expected = f"Cannot delete {child} as there are composite alarm(s) depending on it."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: confirm the child alarm genuinely still exists (the delete really was
    # rejected), via an independent read.
    still_there = cw.describe_alarms(AlarmNames=[child])["MetricAlarms"]
    assert len(still_there) == 1, "child alarm should still exist after the rejected delete"

    # Restore: remove the composite alarm, which clears the dependency edge on `child`.
    cw.delete_alarms(AlarmNames=[composite])
    composite_deleted["done"] = True

    # Positive control: the identical DeleteAlarms call on the child now succeeds.
    cw.delete_alarms(AlarmNames=[child])
    child_deleted["done"] = True

    # Independent read confirms the child is genuinely gone.
    gone = cw.describe_alarms(AlarmNames=[child])["MetricAlarms"]
    assert gone == [], f"child alarm should be gone after the now-unblocked delete, found {gone}"


def _error(fn):
    """(code, message) of the ClientError fn() raises. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last if last is not None and predicate(last) else None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
