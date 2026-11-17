"""describe-alarms-for-metric-rejects-namespace-with-a-leading-colon."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-alarms-for-metric-rejects-namespace-with-a-leading-colon"
GROUP = "validation"
SERVICES = ["cloudwatch"]


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
    """DescribeAlarmsForMetric rejects a Namespace starting with ':' with the modeled
    pattern's exact validation message; the identical namespace without the colon still
    finds the alarm.
    """
    cw = ctx.client("cloudwatch")

    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    metric_name = "ValidationProbeMetric"
    alarm_name = ctx.unique_name("sim2real-behav-cwprobe-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=80.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    found = cw.describe_alarms_for_metric(Namespace=namespace, MetricName=metric_name)
    found_names = {a["AlarmName"] for a in found["MetricAlarms"]}
    assert found_names == {alarm_name}, (
        f"DescribeAlarmsForMetric with the real namespace: expected {{{alarm_name!r}}}, got {found_names}"
    )

    colon_namespace = ":" + namespace
    expected = (
        "ValidationError",
        f"1 validation error detected: Value '{colon_namespace}' at 'namespace' failed to satisfy "
        f"constraint: Member must satisfy regular expression pattern: [^:].*",
    )
    expect_error(
        lambda: cw.describe_alarms_for_metric(Namespace=colon_namespace, MetricName=metric_name),
        *expected,
    )

    found_again = cw.describe_alarms_for_metric(Namespace=namespace, MetricName=metric_name)
    found_names_again = {a["AlarmName"] for a in found_again["MetricAlarms"]}
    assert found_names_again == {alarm_name}, (
        f"DescribeAlarmsForMetric with the real namespace after the rejection: "
        f"expected {{{alarm_name!r}}}, got {found_names_again}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
