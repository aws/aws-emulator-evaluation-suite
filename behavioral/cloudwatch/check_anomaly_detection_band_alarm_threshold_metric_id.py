"""anomaly-detection-band-alarm-threshold-metric-id."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "anomaly-detection-band-alarm-threshold-metric-id"
GROUP = 'alarms'
SERVICES = ['cloudwatch']


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _swallow(fn):
    """Run a cleanup callable; a resource that is already gone (ResourceNotFound) is not an error."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFound", "ResourceNotFoundException"):
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A band alarm stores ThresholdMetricId "ad1" naming ANOMALY_DETECTION_BAND(m1, 2) with no
    Threshold; Threshold with ThresholdMetricId, a band operator with a static Threshold and a
    dangling ThresholdMetricId each fail with their exact ValidationError and create no alarm."""
    cw = ctx.client("cloudwatch")
    ns = ctx.unique_name("sim2real-behav-cwprobe-ns-anomaly-")
    metric = "Traffic"
    alarm = ctx.unique_name("sim2real-behav-cwprobe-alarm-anomaly-")
    detector = {"Namespace": ns, "MetricName": metric, "Stat": "Average"}

    cw.put_anomaly_detector(SingleMetricAnomalyDetector=detector)
    ctx.on_cleanup(lambda: _swallow(
        lambda: cw.delete_anomaly_detector(SingleMetricAnomalyDetector=detector)
    ))

    listed = _poll_until(
        lambda: cw.describe_anomaly_detectors(Namespace=ns, MetricName=metric)["AnomalyDetectors"],
        lambda d: len(d) == 1,
        timeout_s=60,
        interval_s=2,
        description="the anomaly detector to be listed for its namespace/metric",
    )
    assert listed[0]["SingleMetricAnomalyDetector"]["Stat"] == "Average", (
        f"the detector must round-trip its Stat, got {listed[0]}"
    )

    metrics_array = [
        {
            "Id": "m1",
            "MetricStat": {
                "Metric": {"Namespace": ns, "MetricName": metric},
                "Period": 300,
                "Stat": "Average",
            },
            "ReturnData": True,
        },
        {
            "Id": "ad1",
            "Expression": "ANOMALY_DETECTION_BAND(m1, 2)",
            "ReturnData": True,
        },
    ]

    def describe():
        alarms = cw.describe_alarms(AlarmNames=[alarm], AlarmTypes=["MetricAlarm"])["MetricAlarms"]
        assert len(alarms) == 1, f"expected exactly one alarm named {alarm}, got {alarms}"
        return alarms[0]

    # --- Positive: band alarm with ThresholdMetricId and NO Threshold ---
    cw.put_metric_alarm(
        AlarmName=alarm,
        Metrics=metrics_array,
        ThresholdMetricId="ad1",
        ComparisonOperator="GreaterThanUpperThreshold",
        EvaluationPeriods=2,
        TreatMissingData="missing",
        ActionsEnabled=False,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _swallow(lambda: cw.delete_alarms(AlarmNames=[alarm])))

    a = describe()
    assert a["ThresholdMetricId"] == "ad1", (
        f"ThresholdMetricId must round-trip as the id of the band expression, got "
        f"{a.get('ThresholdMetricId')!r}"
    )
    assert "Threshold" not in a, (
        f"an anomaly-detection alarm has no static Threshold -- the emulator must not synthesise "
        f"one (e.g. 0.0); got Threshold={a.get('Threshold')!r}"
    )
    assert a["ComparisonOperator"] == "GreaterThanUpperThreshold", (
        f"expected ComparisonOperator=GreaterThanUpperThreshold, got {a.get('ComparisonOperator')!r}"
    )
    returned = {q["Id"]: q for q in a.get("Metrics", [])}
    assert set(returned) == {"m1", "ad1"}, (
        f"the alarm must store its full Metrics array, got ids {sorted(returned)}"
    )
    assert returned["ad1"]["Expression"] == "ANOMALY_DETECTION_BAND(m1, 2)", (
        f"the band expression must round-trip verbatim, got {returned['ad1'].get('Expression')!r}"
    )
    assert returned["m1"]["MetricStat"]["Period"] == 300, (
        f"the referenced MetricStat must round-trip, got {returned['m1']}"
    )
    # A metric-math alarm carries no top-level single-metric fields.
    for field in ("MetricName", "Namespace", "Statistic", "Period"):
        assert field not in a, (
            f"an alarm defined by a Metrics array must not also report a top-level {field}; got {a.get(field)!r}"
        )

    # --- Negative 1: Threshold and ThresholdMetricId are mutually exclusive ---
    both = ctx.unique_name("sim2real-behav-cwprobe-alarm-anomaly-both-")
    code, message = _err(lambda: cw.put_metric_alarm(
        AlarmName=both,
        Metrics=metrics_array,
        ThresholdMetricId="ad1",
        Threshold=100.0,
        ComparisonOperator="GreaterThanUpperThreshold",
        EvaluationPeriods=2,
        ActionsEnabled=False,
    ))
    assert code == "ValidationError", (
        f"specifying both Threshold and ThresholdMetricId is ambiguous and must be rejected; got {code!r}"
    )
    expected = "Threshold and ThresholdMetricId cannot both be set"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    assert cw.describe_alarms(AlarmNames=[both])["MetricAlarms"] == [], (
        f"the rejected PutMetricAlarm must not have created {both}"
    )

    # --- Negative 2: a band operator with a static threshold is not a band alarm ---
    static = ctx.unique_name("sim2real-behav-cwprobe-alarm-anomaly-static-")
    code, message = _err(lambda: cw.put_metric_alarm(
        AlarmName=static,
        Namespace=ns,
        MetricName=metric,
        Statistic="Average",
        Period=300,
        Threshold=100.0,
        ComparisonOperator="GreaterThanUpperThreshold",
        EvaluationPeriods=2,
        ActionsEnabled=False,
    ))
    assert code == "ValidationError", (
        f"GreaterThanUpperThreshold is only meaningful against an anomaly band, so using it with a "
        f"static Threshold and no ThresholdMetricId must be rejected; got {code!r}"
    )
    expected = "ComparisonOperators for ranges require ThresholdMetricId to be set"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    assert cw.describe_alarms(AlarmNames=[static])["MetricAlarms"] == [], (
        f"the rejected PutMetricAlarm must not have created {static}"
    )

    # --- Negative 3: ThresholdMetricId pointing at an id that is not in Metrics ---
    dangling = ctx.unique_name("sim2real-behav-cwprobe-alarm-anomaly-dangling-")
    code, message = _err(lambda: cw.put_metric_alarm(
        AlarmName=dangling,
        Metrics=metrics_array,
        ThresholdMetricId="ad_missing",
        ComparisonOperator="GreaterThanUpperThreshold",
        EvaluationPeriods=2,
        ActionsEnabled=False,
    ))
    assert code == "ValidationError", (
        f"ThresholdMetricId must resolve to a query in the alarm's own Metrics array; a dangling "
        f"reference must be rejected; got {code!r}"
    )
    expected = "Metrics list must contain exactly one metric matching the ThresholdMetricId parameter"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    assert cw.describe_alarms(AlarmNames=[dangling])["MetricAlarms"] == [], (
        f"the rejected PutMetricAlarm must not have created {dangling}"
    )

    # --- Control: the valid band alarm survived every rejection intact ---
    control = describe()
    assert control["ThresholdMetricId"] == "ad1" and "Threshold" not in control, (
        f"the valid anomaly-detection alarm must be unchanged after the rejections, got {control}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
