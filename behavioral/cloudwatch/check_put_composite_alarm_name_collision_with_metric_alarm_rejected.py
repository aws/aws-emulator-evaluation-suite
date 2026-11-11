"""put-composite-alarm-name-collision-with-metric-alarm-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-composite-alarm-name-collision-with-metric-alarm-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutCompositeAlarm with the AlarmName of an existing metric alarm is rejected with ValidationError
    "AlarmName [<name>] is already used by another alarm of a different type" and leaves only the metric
    alarm; once that alarm is deleted the same call succeeds, as does one with a unique name."""
    cw = ctx.client("cloudwatch")
    shared_name = ctx.unique_name("sim2real-behav-alarm-collide-")
    placeholder_name = ctx.unique_name("sim2real-behav-alarm-placeholder-")
    composite_name = ctx.unique_name("sim2real-behav-composite-")

    cw.put_metric_alarm(
        AlarmName=shared_name,
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Statistic="Average",
        Period=300,
        EvaluationPeriods=1,
        Threshold=90.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[shared_name]))

    # The AlarmRule must reference an alarm that actually exists, so the only
    # possible rejection reason for PutCompositeAlarm below is the AlarmName
    # collision itself, not a dangling ALARM() reference.
    cw.put_metric_alarm(
        AlarmName=placeholder_name,
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Statistic="Average",
        Period=300,
        EvaluationPeriods=1,
        Threshold=90.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[placeholder_name]))

    code, message = _client_error(
        lambda: cw.put_composite_alarm(
            AlarmName=shared_name, AlarmRule=f'ALARM("{placeholder_name}")'
        )
    )
    assert code == "ValidationError", f"unexpected error code: {code!r}"
    expected_message = f"AlarmName [{shared_name}] is already used by another alarm of a different type"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: only the original metric alarm exists under that name.
    described = cw.describe_alarms(
        AlarmNames=[shared_name], AlarmTypes=["MetricAlarm", "CompositeAlarm"]
    )
    assert len(described["MetricAlarms"]) == 1
    assert described["CompositeAlarms"] == []

    # Restore leg: the block is a property of the occupied name, not the name
    # string itself. Remove the blocking metric alarm and the identical
    # PutCompositeAlarm call against that same AlarmName must now succeed.
    cw.delete_alarms(AlarmNames=[shared_name])
    put_resp = cw.put_composite_alarm(
        AlarmName=shared_name, AlarmRule=f'ALARM("{placeholder_name}")'
    )
    assert put_resp["ResponseMetadata"]["HTTPStatusCode"] == 200, put_resp
    # The composite now under shared_name depends on the placeholder, so it must be
    # deleted before the placeholder's own cleanup runs.
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[shared_name]))
    _poll_composite_alarm_visible(cw, shared_name)
    restored = cw.describe_alarms(
        AlarmNames=[shared_name], AlarmTypes=["MetricAlarm", "CompositeAlarm"]
    )
    assert restored["MetricAlarms"] == []
    assert len(restored["CompositeAlarms"]) == 1

    # Positive control: a composite alarm with a distinct name still succeeds.
    put_resp = cw.put_composite_alarm(AlarmName=composite_name, AlarmRule=f'ALARM("{placeholder_name}")')
    assert put_resp["ResponseMetadata"]["HTTPStatusCode"] == 200, put_resp
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[composite_name]))
    _poll_composite_alarm_visible(cw, composite_name)


def _poll_composite_alarm_visible(cw, name: str, timeout_s: float = 30.0, interval_s: float = 2.0) -> None:
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["CompositeAlarm"])
        if len(last["CompositeAlarms"]) == 1:
            return
        time.sleep(interval_s)
    raise AssertionError(f"composite alarm {name!r} never became visible via DescribeAlarms: {last!r}")


def _client_error(fn):
    """Call fn; return the (code, message) of the ClientError it raises.

    Raises AssertionError when the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
