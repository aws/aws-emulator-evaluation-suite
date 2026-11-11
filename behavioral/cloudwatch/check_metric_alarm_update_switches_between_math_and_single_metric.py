"""metric-alarm-update-switches-between-math-and-single-metric."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "metric-alarm-update-switches-between-math-and-single-metric"
GROUP = "alarm-config"
SERVICES = ["cloudwatch"]

_SINGLE_METRIC_FIELDS = ("MetricName", "Namespace", "Period", "Statistic", "Unit")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutMetricAlarm replaces an alarm's config instead of merging: a Metrics math array reads back
    verbatim with no single-metric fields, an update swaps only the expression query, and switching
    back to single-metric fields clears Metrics and reads back Period 120, MetricName, Namespace, Sum."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealSwitchback")
    alarm_name = ctx.unique_name("sim2real-behav-cwswitch-")

    def _stat(qid: str, metric: str) -> dict:
        return {
            "Id": qid,
            "MetricStat": {
                # DescribeAlarms always echoes an explicit empty Dimensions list, even though
                # none was submitted -- part of what "verbatim" means on this field.
                "Metric": {"Namespace": namespace, "MetricName": metric, "Dimensions": []},
                "Period": 60,
                "Stat": "Sum",
            },
            "ReturnData": False,
        }

    def _describe() -> dict:
        alarms = cw.describe_alarms(AlarmNames=[alarm_name]).get("MetricAlarms", [])
        assert len(alarms) == 1, f"expected exactly one alarm named {alarm_name!r}, got {alarms!r}"
        return alarms[0]

    # --- step 1: a classic single-metric alarm -------------------------------------------- #
    cw.put_metric_alarm(
        AlarmName=alarm_name, Namespace=namespace, MetricName="Requests", Statistic="Sum",
        Period=300, EvaluationPeriods=1, Threshold=100.0,
        ComparisonOperator="GreaterThanThreshold", ActionsEnabled=False,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    first = _describe()
    assert first["Period"] == 300, f"classic alarm Period was {first['Period']!r}, expected 300"
    assert "Metrics" not in first or not first["Metrics"], (
        f"a brand-new classic alarm must carry no Metrics array, got {first.get('Metrics')!r}"
    )

    # --- step 2: switch it to a Metrics math-expression alarm ------------------------------ #
    metrics_v1 = [
        _stat("errors", "Errors"),
        _stat("requests", "Requests"),
        {"Id": "ratio", "Expression": "errors + requests", "Label": "Total", "ReturnData": True},
    ]
    cw.put_metric_alarm(
        AlarmName=alarm_name, Metrics=metrics_v1, EvaluationPeriods=1, Threshold=100.0,
        ComparisonOperator="GreaterThanThreshold", ActionsEnabled=False,
    )
    math_v1 = _describe()
    assert math_v1["Metrics"] == metrics_v1, (
        f"DescribeAlarms Metrics after the first math PutMetricAlarm was "
        f"{math_v1['Metrics']!r}, expected the submitted array {metrics_v1!r} verbatim"
    )
    present = [f for f in _SINGLE_METRIC_FIELDS if math_v1.get(f) is not None]
    assert present == [], (
        f"a Metrics-array alarm must not have single-metric fields invented onto it, but "
        f"{present!r} were present: {({f: math_v1.get(f) for f in present})!r}"
    )

    # --- step 3: an update swaps the expression query, leaving the raw queries alone ------- #
    metrics_v2 = [
        metrics_v1[0], metrics_v1[1],
        {"Id": "ratio", "Expression": "errors / requests", "Label": "Ratio", "ReturnData": True},
    ]
    cw.put_metric_alarm(
        AlarmName=alarm_name, Metrics=metrics_v2, EvaluationPeriods=1, Threshold=100.0,
        ComparisonOperator="GreaterThanThreshold", ActionsEnabled=False,
    )
    math_v2 = _describe()
    assert math_v2["Metrics"] == metrics_v2, (
        f"DescribeAlarms Metrics after the replacement PutMetricAlarm was "
        f"{math_v2['Metrics']!r}, expected {metrics_v2!r} -- the raw queries unchanged and only "
        f"the expression query's Expression/Label swapped"
    )

    # --- step 4: switch back to classic fields -- Metrics must be CLEARED, not merged ------ #
    cw.put_metric_alarm(
        AlarmName=alarm_name, Namespace=namespace, MetricName="Requests", Statistic="Sum",
        Period=120, EvaluationPeriods=1, Threshold=50.0,
        ComparisonOperator="GreaterThanThreshold", ActionsEnabled=False,
    )
    back = _describe()
    assert back.get("Metrics") in (None, []), (
        f"switching back to classic fields must clear the Metrics array, got {back.get('Metrics')!r}"
    )
    assert back["Period"] == 120, f"classic alarm Period was {back['Period']!r}, expected 120"
    assert back["MetricName"] == "Requests", f"MetricName was {back['MetricName']!r}"
    assert back["Namespace"] == namespace, f"Namespace was {back['Namespace']!r}"
    assert back["Statistic"] == "Sum", f"Statistic was {back['Statistic']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
