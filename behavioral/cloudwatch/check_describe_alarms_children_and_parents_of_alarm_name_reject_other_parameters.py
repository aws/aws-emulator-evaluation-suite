"""describe-alarms-children-and-parents-of-alarm-name-reject-other-parameters."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-alarms-children-and-parents-of-alarm-name-reject-other-parameters"
GROUP = "validation"
SERVICES = ["cloudwatch"]

_METRIC_ALARM_DEFAULTS = dict(
    Namespace="AWS/EC2",
    MetricName="CPUUtilization",
    Statistic="Average",
    Period=60,
    EvaluationPeriods=1,
    Threshold=80.0,
    ComparisonOperator="GreaterThanThreshold",
    ActionsEnabled=False,
)

_CHILDREN = (
    "ValidationError",
    "ChildrenOfAlarmName requests cannot be used with the following parameters: "
    "ActionPrefix, AlarmNamePrefix, AlarmNames, AlarmTypes, StateValue",
)
_PARENTS = (
    "ValidationError",
    "ParentsOfAlarmName requests cannot be used with the following parameters: "
    "ActionPrefix, AlarmNamePrefix, AlarmNames, AlarmTypes, StateValue",
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
    """DescribeAlarms rejects ChildrenOfAlarmName or ParentsOfAlarmName combined with any
    other filter, with the exact validation error; used alone, each still succeeds.
    """
    cw = ctx.client("cloudwatch")

    child_alarm = ctx.unique_name("sim2real-behav-cwprobe-child-")
    cw.put_metric_alarm(AlarmName=child_alarm, **_METRIC_ALARM_DEFAULTS)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[child_alarm]))

    composite_alarm = ctx.unique_name("sim2real-behav-cwprobe-composite-")
    cw.put_composite_alarm(
        AlarmName=composite_alarm,
        AlarmRule=f'ALARM("{child_alarm}")',
        ActionsEnabled=False,
    )
    # LIFO: this runs before the child alarm's delete above, since a composite alarm must be
    # deleted before an alarm it references.
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[composite_alarm]))

    # --- ChildrenOfAlarmName: succeeds alone, rejected combined with anything else ---
    children = cw.describe_alarms(ChildrenOfAlarmName=composite_alarm, MaxRecords=50)
    child_names = {a["AlarmName"] for a in children["MetricAlarms"]}
    assert child_names == {child_alarm}, (
        f"ChildrenOfAlarmName alone: expected {{{child_alarm!r}}}, got {child_names}"
    )

    expect_error(
        lambda: cw.describe_alarms(ChildrenOfAlarmName=composite_alarm, AlarmNamePrefix="sim2real"),
        *_CHILDREN,
    )

    children_again = cw.describe_alarms(ChildrenOfAlarmName=composite_alarm, MaxRecords=50)
    child_names_again = {a["AlarmName"] for a in children_again["MetricAlarms"]}
    assert child_names_again == {child_alarm}, (
        f"ChildrenOfAlarmName alone after the rejection: expected {{{child_alarm!r}}}, "
        f"got {child_names_again}"
    )

    # --- ParentsOfAlarmName: succeeds alone, rejected combined with anything else ---
    parents = cw.describe_alarms(ParentsOfAlarmName=child_alarm, MaxRecords=50)
    parent_names = {a["AlarmName"] for a in parents["CompositeAlarms"]}
    assert parent_names == {composite_alarm}, (
        f"ParentsOfAlarmName alone: expected {{{composite_alarm!r}}}, got {parent_names}"
    )

    expect_error(
        lambda: cw.describe_alarms(ParentsOfAlarmName=child_alarm, StateValue="OK"),
        *_PARENTS,
    )

    parents_again = cw.describe_alarms(ParentsOfAlarmName=child_alarm, MaxRecords=50)
    parent_names_again = {a["AlarmName"] for a in parents_again["CompositeAlarms"]}
    assert parent_names_again == {composite_alarm}, (
        f"ParentsOfAlarmName alone after the rejection: expected {{{composite_alarm!r}}}, "
        f"got {parent_names_again}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
