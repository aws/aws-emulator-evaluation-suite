"""alarm-composite-and-actions-metric-alarm-onto-composite-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alarm-composite-and-actions-metric-alarm-onto-composite-name-rejected"
GROUP = "validation"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutMetricAlarm under a composite alarm's name fails with ValidationError "AlarmName [<name>]
    is already used by another alarm of a different type", creates no metric alarm and leaves the
    composite's AlarmRule and AlarmArn unchanged; under a fresh name the same call succeeds."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real/cwname-")
    metric_kwargs = dict(
        Namespace=namespace, MetricName="m", Statistic="Maximum", Period=60,
        EvaluationPeriods=1, Threshold=1.0, ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
    )
    child = ctx.unique_name("sim2real-cwname-child-")
    cw.put_metric_alarm(AlarmName=child, Tags=[{"Key": "sim2real", "Value": CHECK}], **metric_kwargs)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[child]))

    composite = ctx.unique_name("sim2real-cwname-comp-")
    rule = f'ALARM("{child}")'
    cw.put_composite_alarm(
        AlarmName=composite, AlarmRule=rule, ActionsEnabled=False,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[composite]))
    before = _both(cw, composite)
    assert len(before["CompositeAlarms"]) == 1 and before["MetricAlarms"] == [], before

    fresh = ctx.unique_name("sim2real-cwname-fresh-")
    cw.put_metric_alarm(AlarmName=fresh, **metric_kwargs)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[fresh]))
    assert len(_both(cw, fresh)["MetricAlarms"]) == 1, "positive control metric alarm was not created"

    code, message, _ = _attempt(lambda: cw.put_metric_alarm(AlarmName=composite, **metric_kwargs))
    assert code == "ValidationError", (
        f"PutMetricAlarm onto composite {composite!r}'s name must be refused with ValidationError; "
        f"got {code!r} {message!r}"
    )
    expected = f"AlarmName [{composite}] is already used by another alarm of a different type"
    assert message == expected, (
        f"the refusal must say the name is used by an alarm of a different type: expected {expected!r}, "
        f"got {message!r}"
    )
    after = _both(cw, composite)
    assert after["MetricAlarms"] == [], (
        f"the refused PutMetricAlarm created a metric alarm under the composite's name: {after['MetricAlarms']!r}"
    )
    assert len(after["CompositeAlarms"]) == 1, f"the composite vanished: {after!r}"
    assert after["CompositeAlarms"][0]["AlarmRule"] == rule, (
        f"the composite's AlarmRule changed to {after['CompositeAlarms'][0]['AlarmRule']!r}"
    )
    assert after["CompositeAlarms"][0]["AlarmArn"] == before["CompositeAlarms"][0]["AlarmArn"], (
        "the composite's AlarmArn changed across the refused call"
    )


def _both(cw, name: str) -> dict:
    return cw.describe_alarms(AlarmNames=[name], AlarmTypes=["CompositeAlarm", "MetricAlarm"])


def _attempt(fn):
    """(code, message, succeeded). Never a falsy code on unexpected success: '<SUCCEEDED>'."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or "", False
    return "<SUCCEEDED>", "the call was accepted", True


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
