"""invalid-parameter-combination-family."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-parameter-combination-family"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']

def _err(fn):
    """Return the (code, message) of the ClientError fn() raises; a success fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

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

def _safe_delete_anomaly_detector(cw, detector):
    try:
        cw.delete_anomaly_detector(SingleMetricAnomalyDetector=detector)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _safe_delete_metric_stream(cw, name):
    """DeleteMetricStream of an already-deleted name succeeds, so any error is a real failure."""
    cw.delete_metric_stream(Name=name)

@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutMetricData, Put/DeleteAnomalyDetector and PutMetricStream reject mutually exclusive
    parameters with exact InvalidParameterCombination errors, change nothing, and each
    succeeds with one of the parameters alone."""
    cw = ctx.client("cloudwatch")
    account = ctx.client("sts").get_caller_identity()["Account"]

    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    code, message = _err(lambda: cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{
            "MetricName": "Conflicting",
            "Value": 5.0,
            "StatisticValues": {"SampleCount": 1.0, "Sum": 5.0, "Minimum": 5.0, "Maximum": 5.0},
        }],
    ))
    assert code == "InvalidParameterCombination", (
        f"PutMetricData: expected InvalidParameterCombination for Value+StatisticValues, got {code}"
    )
    assert message == 'The parameters MetricData.member.1.Value and MetricData.member.1.StatisticValues are mutually exclusive and you have specified both.', f"PutMetricData: unexpected message {message!r}"

    # Top-level Namespace/MetricName/Stat and SingleMetricAnomalyDetector together.
    metric_name = "ConflictMetric"
    code, message = _err(lambda: cw.put_anomaly_detector(
        Namespace=namespace,
        MetricName=metric_name,
        Stat="Average",
        SingleMetricAnomalyDetector={"Namespace": namespace, "MetricName": metric_name, "Stat": "Average"},
    ))
    assert code == "InvalidParameterCombination", (
        f"PutAnomalyDetector: expected InvalidParameterCombination for legacy+new-style fields, got {code}"
    )
    assert message == 'Either single metric attributes, SingleMetricAnomalyDetector or MetricMathAnomalyDetector can be set, found single metric attributes, SingleMetricAnomalyDetector.', f"PutAnomalyDetector: unexpected message {message!r}"
    detectors = cw.describe_anomaly_detectors(Namespace=namespace, MetricName=metric_name).get(
        "AnomalyDetectors", []
    )
    assert detectors == [], "a rejected PutAnomalyDetector call must not register a detector"

    single_metric_detector = {"Namespace": namespace, "MetricName": metric_name, "Stat": "Average"}
    cw.put_anomaly_detector(SingleMetricAnomalyDetector=single_metric_detector)
    ctx.on_cleanup(lambda: _safe_delete_anomaly_detector(cw, single_metric_detector))
    _poll_until(
        lambda: cw.describe_anomaly_detectors(Namespace=namespace, MetricName=metric_name).get(
            "AnomalyDetectors", []
        ),
        lambda ds: len(ds) == 1,
        timeout_s=20, interval_s=1.0,
        description="anomaly detector visible after a valid PutAnomalyDetector",
    )

    code, message = _err(lambda: cw.delete_anomaly_detector(
        Namespace=namespace,
        MetricName=metric_name,
        Stat="Average",
        SingleMetricAnomalyDetector={"Namespace": namespace, "MetricName": metric_name, "Stat": "Average"},
    ))
    assert code == "InvalidParameterCombination", (
        f"DeleteAnomalyDetector: expected InvalidParameterCombination for legacy+new-style fields, got {code}"
    )
    assert message == 'Either single metric attributes, SingleMetricAnomalyDetector or MetricMathAnomalyDetector can be set, found single metric attributes, SingleMetricAnomalyDetector.', f"DeleteAnomalyDetector: unexpected message {message!r}"
    detectors = cw.describe_anomaly_detectors(Namespace=namespace, MetricName=metric_name).get(
        "AnomalyDetectors", []
    )
    assert len(detectors) == 1, "a rejected DeleteAnomalyDetector call must leave the real detector untouched"

    cw.delete_anomaly_detector(SingleMetricAnomalyDetector=single_metric_detector)
    _poll_until(
        lambda: cw.describe_anomaly_detectors(Namespace=namespace, MetricName=metric_name).get(
            "AnomalyDetectors", []
        ),
        lambda ds: ds == [],
        timeout_s=20, interval_s=1.0,
        description="anomaly detector gone after a valid DeleteAnomalyDetector",
    )

    # GetMetricStatistics accepts Statistics and ExtendedStatistics together despite the
    # documented "not both" constraint, so it is exercised only as a successful read.
    now = datetime.now(timezone.utc)
    cw.put_metric_data(
        Namespace=namespace, MetricData=[{"MetricName": "Probe", "Value": 1.0}]
    )

    def probe_stats():
        return cw.get_metric_statistics(
            Namespace=namespace,
            MetricName="Probe",
            StartTime=now - timedelta(minutes=10),
            EndTime=now + timedelta(minutes=5),
            Period=60,
            Statistics=["Average"],
            ExtendedStatistics=["p99"],
        ).get("Datapoints", [])

    _poll_until(probe_stats, lambda dp: len(dp) > 0, timeout_s=60, interval_s=3)

    # CloudWatch does not resolve the Firehose/role ARNs at creation, so fabricated ones suffice.
    stream_name = ctx.unique_name("sim2real-behav-cwprobe-mstream-conflict-")
    firehose_arn = f"arn:aws:firehose:{ctx.region}:{account}:deliverystream/{stream_name}"
    role_arn = f"arn:aws:iam::{account}:role/{stream_name}"
    code, message = _err(lambda: cw.put_metric_stream(
        Name=stream_name,
        FirehoseArn=firehose_arn,
        RoleArn=role_arn,
        OutputFormat="json",
        IncludeFilters=[{"Namespace": "AWS/EC2"}],
        ExcludeFilters=[{"Namespace": "AWS/S3"}],
    ))
    assert code == "InvalidParameterCombination", (
        f"PutMetricStream: expected InvalidParameterCombination for IncludeFilters+ExcludeFilters, got {code}"
    )
    assert message == 'IncludeFilters and ExcludeFilters cannot both be present', f"PutMetricStream: unexpected message {message!r}"
    code, message = _err(lambda: cw.get_metric_stream(Name=stream_name))
    assert code == "ResourceNotFoundException", (
        f"GetMetricStream: a metric stream rejected for a bad filter combination must not exist, got {code}"
    )
    assert message == "", f"GetMetricStream: unexpected message {message!r}"

    live_stream_name = ctx.unique_name("sim2real-behav-cwprobe-mstream-live-")
    live_firehose_arn = f"arn:aws:firehose:{ctx.region}:{account}:deliverystream/{live_stream_name}"
    live_role_arn = f"arn:aws:iam::{account}:role/{live_stream_name}"
    cw.put_metric_stream(
        Name=live_stream_name,
        FirehoseArn=live_firehose_arn,
        RoleArn=live_role_arn,
        OutputFormat="json",
        IncludeFilters=[{"Namespace": "AWS/EC2"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_metric_stream(cw, live_stream_name))
    desc = cw.get_metric_stream(Name=live_stream_name)
    assert desc["State"] == "running", (
        f"a valid PutMetricStream call should create a running stream, got {desc['State']!r}"
    )

    cw.delete_metric_stream(Name=live_stream_name)
    code, message = _err(lambda: cw.get_metric_stream(Name=live_stream_name))
    assert code == "ResourceNotFoundException", (
        f"GetMetricStream: expected ResourceNotFoundException after deleting the live stream, got {code}"
    )
    assert message == "", f"GetMetricStream: unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
