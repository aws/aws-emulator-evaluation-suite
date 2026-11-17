"""describe-alarms-rejects-an-unmodelled-alarm-type."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-alarms-rejects-an-unmodelled-alarm-type"
GROUP = "validation"
SERVICES = ["cloudwatch"]

_UNMODELLED_ALARM_TYPE = (
    "ValidationError",
    "1 validation error detected: Value '[NotARealType]' at 'alarmTypes' failed to satisfy "
    "constraint: Member must satisfy constraint: [Member must satisfy enum value set: "
    "[MetricAlarm, CompositeAlarm]]",
)


def expect_error(fn, code, message):
    """Call fn(); assert it raises exactly (code, message). An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        got = (error.get("Code"), error.get("Message"))
        assert got == (code, message), f"expected ({code!r}, {message!r}), got {got}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAlarms rejects an AlarmTypes value outside CompositeAlarm/MetricAlarm/LogAlarm
    with the exact enum validation message; a modelled value still succeeds.
    """
    cw = ctx.client("cloudwatch")

    alarm_name = ctx.unique_name("sim2real-behav-cwprobe-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=80.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    found = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["MetricAlarm"])
    found_names = {a["AlarmName"] for a in found["MetricAlarms"]}
    assert found_names == {alarm_name}, (
        f"DescribeAlarms with AlarmTypes=['MetricAlarm']: expected {{{alarm_name!r}}}, got {found_names}"
    )

    expect_error(
        lambda: cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["NotARealType"]),
        *_UNMODELLED_ALARM_TYPE,
    )

    found_again = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["MetricAlarm"])
    found_names_again = {a["AlarmName"] for a in found_again["MetricAlarms"]}
    assert found_names_again == {alarm_name}, (
        f"DescribeAlarms with AlarmTypes=['MetricAlarm'] after the rejection: "
        f"expected {{{alarm_name!r}}}, got {found_names_again}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
