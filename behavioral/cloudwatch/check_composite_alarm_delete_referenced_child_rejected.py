"""composite-alarm-delete-referenced-child-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "composite-alarm-delete-referenced-child-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAlarms on a metric alarm a composite's AlarmRule references fails with ValidationError
    "Cannot delete <name> as there are composite alarm(s) depending on it." and the alarm stays;
    after the composite is deleted, the same delete succeeds."""
    cw = ctx.client("cloudwatch")
    child = ctx.unique_name("sim2real-alarm-child-")
    composite = ctx.unique_name("sim2real-alarm-composite-")
    namespace = ctx.unique_name("Sim2RealBehavioral-")
    tags_kv = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

    cw.put_metric_alarm(
        AlarmName=child,
        Namespace=namespace,
        MetricName="InvocationCount",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=tags_kv,
    )
    child_deleted = {"done": False}
    # Register child cleanup FIRST: LIFO teardown deletes the composite (registered
    # second) before the child, since the child can't be deleted while referenced.
    ctx.on_cleanup(lambda: None if child_deleted["done"] else cw.delete_alarms(AlarmNames=[child]))

    cw.put_composite_alarm(AlarmName=composite, AlarmRule=f'ALARM("{child}")', Tags=tags_kv)
    composite_deleted = {"done": False}
    ctx.on_cleanup(lambda: None if composite_deleted["done"] else cw.delete_alarms(AlarmNames=[composite]))

    # PutCompositeAlarm's dependency graph (which children each composite references)
    # is not necessarily indexed synchronously -- give it a bounded window to become
    # visible via ChildrenOfAlarmName before relying on it to reject the child delete.
    _wait_for_child_reference(ctx, composite, child, timeout_s=60.0)

    # CloudWatch rejects this with a generic ValidationError code, not the "ResourceConflict"
    # shape the API model documents for DeleteAlarms.
    code, message = _refusal(lambda: cw.delete_alarms(AlarmNames=[child]))
    assert code == "ValidationError", (
        f"expected ValidationError deleting a referenced child, got {code} ({message!r})"
    )
    assert message == (
        f"Cannot delete {child} as there are composite alarm(s) depending on it."
    ), (
        f"unexpected ValidationError message {message!r}"
    )

    # Effect absent: the rejected delete must not have touched the child alarm.
    still_there = cw.describe_alarms(AlarmNames=[child])["MetricAlarms"]
    assert len(still_there) == 1 and still_there[0]["AlarmName"] == child, (
        f"child alarm must survive the rejected delete untouched, got {still_there}"
    )

    # Restore: once the composite is deleted, the identical
    # delete call must succeed -- this is what distinguishes "rejects this specific
    # conflict" from "rejects every DeleteAlarms call".
    cw.delete_alarms(AlarmNames=[composite])
    composite_deleted["done"] = True

    cw.delete_alarms(AlarmNames=[child])
    child_deleted["done"] = True

    remaining = cw.describe_alarms(AlarmNames=[child])["MetricAlarms"]
    assert remaining == [], f"child alarm should be gone after the unblocked delete, got {remaining}"


def _wait_for_child_reference(ctx, composite: str, child: str, timeout_s: float, interval_s: float = 3.0) -> None:
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    children = []
    while time.monotonic() < deadline:
        children = cw.describe_alarms(ChildrenOfAlarmName=composite).get("MetricAlarms", [])
        if any(c["AlarmName"] == child for c in children):
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"composite alarm {composite} never showed {child} as a child within {timeout_s}s: {children}"
    )


def _refusal(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) of the refusal. An unexpected
    SUCCESS raises, so a target accepting a call AWS refuses is never reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
