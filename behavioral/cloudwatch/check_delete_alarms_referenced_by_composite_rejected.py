"""delete-alarms-referenced-by-composite-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-alarms-referenced-by-composite-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAlarms on a metric alarm referenced by a composite alarm's AlarmRule is rejected with
    ValidationError -- both alone and when named together with the composite in the same batch."""
    cw = ctx.client("cloudwatch")
    child_name = ctx.unique_name("sim2real-child-alarm-")
    composite_name = ctx.unique_name("sim2real-composite-alarm-")

    cw.put_metric_alarm(
        AlarmName=child_name,
        MetricName="CPUUtilization",
        Namespace="AWS/EC2",
        Statistic="Average",
        Period=300,
        EvaluationPeriods=1,
        Threshold=80.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    cw.put_composite_alarm(
        AlarmName=composite_name,
        AlarmRule=f'ALARM("{child_name}")',
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_composite_then_child(cw, composite_name, child_name))

    # The child alarm is load-bearing for the composite's AlarmRule -- deleting it directly
    # must be rejected, not silently allowed to orphan the composite alarm's expression. Real
    # CloudWatch rejects this with a generic ValidationError (not the "ResourceConflict" shape
    # the API model documents for DeleteAlarms).
    code, message = _error(lambda: cw.delete_alarms(AlarmNames=[child_name]))
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected_message = f"Cannot delete {child_name} as there are composite alarm(s) depending on it."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The child alarm must still exist -- the rejected call had no partial effect.
    still = cw.describe_alarms(AlarmNames=[child_name], AlarmTypes=["MetricAlarm"])
    still_alarms = still.get("MetricAlarms", [])
    assert len(still_alarms) == 1, f"expected the child alarm to survive the rejected delete, found {still_alarms!r}"

    # A single DeleteAlarms naming the composite and the child TOGETHER is also rejected --
    # DeleteAlarms validates dependencies against the pre-request state, so a batch cannot
    # self-order itself out of the conflict even though removing the composite in the same
    # request would have freed the child.
    combined_code, combined_msg = _error(
        lambda: cw.delete_alarms(AlarmNames=[composite_name, child_name])
    )
    assert combined_code == "ValidationError", (
        f"expected ValidationError for a combined composite+child DeleteAlarms, got {combined_code}: {combined_msg}"
    )
    expected_combined = f"Cannot delete {child_name} as there are composite alarm(s) depending on it."
    assert combined_msg == expected_combined, f"expected message {expected_combined!r}, got {combined_msg!r}"
    still_after_combined = cw.describe_alarms(
        AlarmNames=[composite_name, child_name], AlarmTypes=["MetricAlarm", "CompositeAlarm"]
    )
    assert len(still_after_combined.get("MetricAlarms", [])) == 1, (
        f"the rejected combined delete should have left the child alarm in place: {still_after_combined!r}"
    )
    assert len(still_after_combined.get("CompositeAlarms", [])) == 1, (
        f"the rejected combined delete should have left the composite alarm in place: {still_after_combined!r}"
    )

    # Deleting the composite first, then the child, as two SEPARATE requests is the correct,
    # permitted path.
    cw.delete_alarms(AlarmNames=[composite_name])
    cw.delete_alarms(AlarmNames=[child_name])
    remaining = cw.describe_alarms(
        AlarmNames=[composite_name, child_name], AlarmTypes=["MetricAlarm", "CompositeAlarm"]
    )
    assert remaining.get("MetricAlarms", []) == [], f"child alarm should be gone, found {remaining!r}"
    assert remaining.get("CompositeAlarms", []) == [], f"composite alarm should be gone, found {remaining!r}"


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return the botocore (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_composite_then_child(cw, composite_name: str, child_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cw.delete_alarms(AlarmNames=[composite_name])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise
    try:
        cw.delete_alarms(AlarmNames=[child_name])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
