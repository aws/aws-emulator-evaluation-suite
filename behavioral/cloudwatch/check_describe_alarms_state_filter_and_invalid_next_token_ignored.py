"""describe-alarms-state-filter-and-invalid-next-token-ignored."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "describe-alarms-state-filter-and-invalid-next-token-ignored"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarms with StateValue ALARM or OK returns only the alarm SetAlarmState put in that
    state, and with a garbage NextToken it does not fail with InvalidNextToken but returns both
    named alarms, as if no token had been sent."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-ns-")
    alarm_ok = ctx.unique_name("sim2real-behav-alarm-ok-")
    alarm_in_alarm = ctx.unique_name("sim2real-behav-alarm-alarm-")

    _put_alarm(ctx, alarm_ok, namespace, "OkMetric")
    _put_alarm(ctx, alarm_in_alarm, namespace, "AlarmMetric")

    cw.set_alarm_state(AlarmName=alarm_ok, StateValue="OK", StateReason="behavioral test")
    cw.set_alarm_state(AlarmName=alarm_in_alarm, StateValue="ALARM", StateReason="behavioral test")

    resp = cw.describe_alarms(AlarmNames=[alarm_ok, alarm_in_alarm], StateValue="ALARM")
    names = {a["AlarmName"] for a in resp["MetricAlarms"]}
    assert names == {alarm_in_alarm}, f"expected only {alarm_in_alarm} in ALARM state, got {names}"
    assert resp["MetricAlarms"][0]["StateValue"] == "ALARM", (
        f"expected StateValue ALARM on the filtered alarm, got {resp['MetricAlarms'][0]['StateValue']}"
    )

    resp_ok = cw.describe_alarms(AlarmNames=[alarm_ok, alarm_in_alarm], StateValue="OK")
    names_ok = {a["AlarmName"] for a in resp_ok["MetricAlarms"]}
    assert names_ok == {alarm_ok}, f"expected only {alarm_ok} in OK state, got {names_ok}"

    # A stale/garbage NextToken does not raise InvalidNextToken here: the request still
    # succeeds and is scoped by AlarmNames like any other DescribeAlarms call, returning the
    # check's two alarms.
    resp_token = cw.describe_alarms(
        AlarmNames=[alarm_ok, alarm_in_alarm], NextToken="garbage-not-a-real-token"
    )
    names_token = {a["AlarmName"] for a in resp_token["MetricAlarms"]}
    assert names_token == {alarm_ok, alarm_in_alarm}, (
        f"expected the garbage NextToken to be ignored and both alarms returned, got {names_token}"
    )


def _put_alarm(ctx: Any, name: str, namespace: str, metric_name: str) -> None:
    cw = ctx.client("cloudwatch")
    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
