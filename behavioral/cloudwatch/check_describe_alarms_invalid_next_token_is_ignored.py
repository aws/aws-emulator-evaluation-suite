"""describe-alarms-invalid-next-token-is-ignored."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-alarms-invalid-next-token-is-ignored"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarms with a garbage NextToken does not fail with InvalidNextToken:
    it returns the same first page, scoped to the check's own alarm, as the call
    without a token."""
    cw = ctx.client("cloudwatch")

    # Scope to an alarm this check creates: a baseline of pre-existing alarms can
    # be empty (making the equality below vacuous) or change between the two calls.
    alarm_name = ctx.unique_name("sim2real-behav-cwprobe-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=ctx.unique_name("sim2real-behav-ns-"),
        MetricName="CPUUtilization",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=80.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
        Tags=[{"Key": "sim2real-behav", "Value": "cwprobe"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    # Baseline: a call with no NextToken succeeds and defines the "first page".
    baseline = cw.describe_alarms(AlarmNames=[alarm_name], MaxRecords=5)
    baseline_names = {a["AlarmName"] for a in baseline["MetricAlarms"]}
    assert baseline_names == {alarm_name}, (
        f"expected the baseline call to return the alarm this check created, "
        f"got {baseline_names}"
    )

    # A garbage NextToken is silently treated as "no token" rather than rejected.
    resp = cw.describe_alarms(
        AlarmNames=[alarm_name], MaxRecords=5, NextToken="not-a-real-token-xyz-123"
    )
    token_names = {a["AlarmName"] for a in resp["MetricAlarms"]}
    assert token_names == baseline_names, (
        f"expected the garbage NextToken to be ignored and the same first page "
        f"returned, got {token_names} vs baseline {baseline_names}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
