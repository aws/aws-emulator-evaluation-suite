"""metric-alarm-recreated-after-delete-is-a-fresh-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "metric-alarm-recreated-after-delete-is-a-fresh-resource"
GROUP = "alarms"
SERVICES = ["cloudwatch"]


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An alarm forced to ALARM and deleted, then recreated under the same name with a different
    Threshold and ComparisonOperator, comes back as a fresh resource: INSUFFICIENT_DATA with no
    carried-over ALARM state, the new configuration, the same AlarmArn and a later AlarmConfigurationUpdatedTimestamp."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-cwrecreate-")
    namespace = ctx.unique_name("sim2real-behav-cwrecreate-ns-")
    ctx.on_cleanup(lambda _n=alarm_name: cw.delete_alarms(AlarmNames=[_n]))

    def by_name():
        return cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="OriginalMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=80.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    original = _poll_until(by_name, lambda r: len(r) > 0, timeout_s=20, interval_s=2)[0]
    expected_arn = f"arn:aws:cloudwatch:{ctx.region}:{ctx.account}:alarm:{alarm_name}"
    assert original["AlarmArn"] == expected_arn, (
        f"expected AlarmArn {expected_arn!r}, got {original['AlarmArn']!r}"
    )
    original_config_updated = original["AlarmConfigurationUpdatedTimestamp"]

    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="forced for the recreate check")
    _poll_until(
        by_name,
        lambda r: r and r[0]["StateValue"] == "ALARM",
        timeout_s=20, interval_s=2,
        description="the forced transition to ALARM",
    )

    cw.delete_alarms(AlarmNames=[alarm_name])
    gone = _poll_until(by_name, lambda r: r == [], timeout_s=20, interval_s=2, description="the alarm gone after delete")
    assert gone == [], f"DescribeAlarms(AlarmNames=[{alarm_name!r}]) still returns the deleted alarm: {gone!r}"

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="OriginalMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=55.0,
        ComparisonOperator="LessThanThreshold",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    recreated_list = _poll_until(by_name, lambda r: len(r) > 0, timeout_s=20, interval_s=2)
    assert len(recreated_list) == 1, (
        f"expected exactly one alarm named {alarm_name!r} after the recreate, got {recreated_list!r}"
    )
    recreated = recreated_list[0]

    assert recreated["StateValue"] == "INSUFFICIENT_DATA", (
        f"expected the recreated alarm's StateValue to be INSUFFICIENT_DATA with no carried-over "
        f"ALARM, got {recreated['StateValue']!r}"
    )
    assert recreated["Threshold"] == 55.0, f"expected Threshold 55.0, got {recreated['Threshold']!r}"
    assert recreated["ComparisonOperator"] == "LessThanThreshold", (
        f"expected ComparisonOperator LessThanThreshold, got {recreated['ComparisonOperator']!r}"
    )
    assert recreated["AlarmArn"] == expected_arn, (
        f"expected the recreated alarm to keep AlarmArn {expected_arn!r}, got {recreated['AlarmArn']!r}"
    )
    recreated_config_updated = recreated["AlarmConfigurationUpdatedTimestamp"]
    assert recreated_config_updated > original_config_updated, (
        f"expected the recreated alarm's AlarmConfigurationUpdatedTimestamp "
        f"({recreated_config_updated!r}) to be later than the original's "
        f"({original_config_updated!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
