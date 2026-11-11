"""put-metric-alarm-invalid-combo-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-alarm-invalid-combo-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']

def _error(fn):
    """Call fn(); return the botocore Error dict. A SUCCESS raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutMetricAlarm with single-metric fields and a Metrics array together is rejected with
    ValidationError "MetricName should not be set if list of Metrics is set.", and PutCompositeAlarm with a
    malformed AlarmRule with its exact parse error; neither creates an alarm, while each valid form does."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-mixed-")

    # --- Positive control: classic fields ALONE succeed ---
    classic_name = ctx.unique_name("sim2real-behav-cwprobe-alarm-classic-")
    cw.put_metric_alarm(
        AlarmName=classic_name,
        Namespace=namespace,
        MetricName="ClassicMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[classic_name]))
    assert [a["AlarmName"] for a in cw.describe_alarms(AlarmNames=[classic_name]).get("MetricAlarms", [])] == [
        classic_name
    ], "PutMetricAlarm: a valid classic-fields-only alarm must be created and visible"

    # --- Positive control: a Metrics math-expression array ALONE succeeds ---
    metrics_name = ctx.unique_name("sim2real-behav-cwprobe-alarm-metrics-")
    cw.put_metric_alarm(
        AlarmName=metrics_name,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Metrics=[
            {
                "Id": "m1",
                "MetricStat": {
                    "Metric": {"Namespace": namespace, "MetricName": "OtherMetric"},
                    "Period": 60,
                    "Stat": "Average",
                },
                "ReturnData": True,
            }
        ],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[metrics_name]))
    assert [a["AlarmName"] for a in cw.describe_alarms(AlarmNames=[metrics_name]).get("MetricAlarms", [])] == [
        metrics_name
    ], "PutMetricAlarm: a valid Metrics-array-only alarm must be created and visible"

    # --- Negative: PutMetricAlarm rejects classic fields + Metrics array TOGETHER ---
    mixed_name = ctx.unique_name("sim2real-behav-cwprobe-alarm-mixed-")
    error = _error(lambda: cw.put_metric_alarm(
        AlarmName=mixed_name,
        Namespace=namespace,
        MetricName="ClassicMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Metrics=[
            {
                "Id": "m1",
                "MetricStat": {
                    "Metric": {"Namespace": namespace, "MetricName": "OtherMetric"},
                    "Period": 60,
                    "Stat": "Average",
                },
                "ReturnData": True,
            }
        ],
    ))
    assert error.get("Code") == "ValidationError", (
        f"PutMetricAlarm: expected a combination-validation rejection for classic fields + "
        f"Metrics together, got {error}"
    )
    assert error.get("Message") == "MetricName should not be set if list of Metrics is set.", (
        f"PutMetricAlarm: unexpected message for classic fields + Metrics together: {error.get('Message')!r}"
    )
    described = cw.describe_alarms(AlarmNames=[mixed_name]).get("MetricAlarms", [])
    assert described == [], "a rejected PutMetricAlarm call must not create the alarm"

    # --- Positive control: a valid composite rule over a real leaf succeeds ---
    composite_ok_name = ctx.unique_name("sim2real-behav-cwprobe-composite-ok-")
    cw.put_composite_alarm(
        AlarmName=composite_ok_name, AlarmRule=f'ALARM("{classic_name}")'
    )
    # Registered after the leaf cleanups above so LIFO teardown deletes the composite
    # before the metric alarm its rule references (CloudWatch refuses to delete a
    # referenced leaf while a composite rule is live).
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[composite_ok_name]))
    assert [
        a["AlarmName"]
        for a in cw.describe_alarms(
            AlarmNames=[composite_ok_name], AlarmTypes=["CompositeAlarm"]
        ).get("CompositeAlarms", [])
    ] == [composite_ok_name], (
        "PutCompositeAlarm: a valid rule over an existing leaf must be created and visible"
    )

    # --- Negative: PutCompositeAlarm rejects a structurally malformed AlarmRule ---
    composite_name = ctx.unique_name("sim2real-behav-cwprobe-composite-badrule-")
    error = _error(lambda: cw.put_composite_alarm(
        AlarmName=composite_name, AlarmRule='ALARM("leaf") AND AND ((('
    ))
    assert error.get("Code") == "ValidationError", (
        f"PutCompositeAlarm: expected a validation-flavored rejection for a malformed AlarmRule, got {error}"
    )
    assert error.get("Message") == "Error in AlarmRule [Unsupported token 'AND' at char 18, must be: '(', 'NOT', AT_LEAST, TRUE or FALSE, ALARM, OK, or INSUFFICIENT_DATA]", (
        "PutCompositeAlarm: the refusal must attribute itself to a rule PARSE failure (distinct "
        f"from an unknown-child or existence refusal, which share the same code), got {error.get('Message')!r}"
    )
    composite_described = cw.describe_alarms(
        AlarmNames=[composite_name], AlarmTypes=["CompositeAlarm"]
    ).get("CompositeAlarms", [])
    assert composite_described == [], "a rejected PutCompositeAlarm call must not create the alarm"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
