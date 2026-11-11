"""delete-alarm-referenced-by-composite-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-alarm-referenced-by-composite-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAlarms on a metric alarm a composite's AlarmRule references fails with ValidationError
    "Cannot delete <name> as there are composite alarm(s) depending on it." and the alarm stays; an
    unreferenced alarm deletes, and the referenced one deletes once the composite is deleted."""
    cw = ctx.client("cloudwatch")
    child_name = ctx.unique_name("sim2real-behav-refchild-")
    composite_name = ctx.unique_name("sim2real-behav-refcomposite-")
    control_name = ctx.unique_name("sim2real-behav-refcontrol-")
    namespace = ctx.unique_name("Sim2RealBehav/")

    alarm_kwargs = dict(
        Namespace=namespace,
        MetricName="NeverPublished",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )

    # Positive control: an alarm with no composite referencing it deletes cleanly, so the
    # rejection asserted below is attributable to the reference -- not to DeleteAlarms being
    # broken or denied outright.
    cw.put_metric_alarm(AlarmName=control_name, **alarm_kwargs)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[control_name]))
    cw.delete_alarms(AlarmNames=[control_name])
    control_gone = cw.describe_alarms(AlarmNames=[control_name])["MetricAlarms"]
    assert control_gone == [], f"positive control: unreferenced alarm should delete, got {control_gone}"

    cw.put_metric_alarm(AlarmName=child_name, **alarm_kwargs)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[child_name]))

    cw.put_composite_alarm(AlarmName=composite_name, AlarmRule=f'ALARM("{child_name}")')
    # Registered after the child's cleanup so LIFO teardown removes the composite alarm first,
    # clearing the reference before the child alarm delete is attempted.
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[composite_name]))

    # Poll until the composite alarm is fully registered (visible, with its rule and an
    # evaluated StateValue) before relying on its dependency edge to reject the child delete.
    registered = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[composite_name], AlarmTypes=["CompositeAlarm"]).get(
            "CompositeAlarms", []
        ),
        lambda alarms: bool(alarms)
        and alarms[0].get("AlarmRule") == f'ALARM("{child_name}")'
        and alarms[0].get("StateValue") is not None,
        timeout_s=30.0,
    )
    assert registered, "composite alarm never became visible/registered via DescribeAlarms"

    code, message = _error(lambda: cw.delete_alarms(AlarmNames=[child_name]))
    assert code == "ValidationError", f"expected ValidationError deleting a composite-referenced alarm, got {code}"
    expected_message = f"Cannot delete {child_name} as there are composite alarm(s) depending on it."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The child alarm must still exist since the delete was rejected.
    still_there = cw.describe_alarms(AlarmNames=[child_name])["MetricAlarms"]
    assert len(still_there) == 1, still_there

    # Restore: remove the reference, then the identical delete call must now succeed and the
    # child must be independently confirmed gone.
    cw.delete_alarms(AlarmNames=[composite_name])
    _delete_until_gone(cw, child_name, timeout_s=30.0)
    now_gone = cw.describe_alarms(AlarmNames=[child_name])["MetricAlarms"]
    assert now_gone == [], f"child alarm should be deletable once the reference is removed: {now_gone}"


def _error(fn):
    """Call fn(); return the botocore (Code, Message). An unexpected SUCCESS raises, so an emulator
    accepting a call AWS refuses is never reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_until_gone(cw, name, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            cw.delete_alarms(AlarmNames=[name])
            return
        except ClientError as exc:
            last_error = exc.response["Error"]["Code"]
        time.sleep(interval_s)
    raise AssertionError(f"delete of {name} kept failing with {last_error!r} after its reference was removed")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
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
