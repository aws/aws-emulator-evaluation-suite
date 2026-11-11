"""internal-service-fault-family."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "internal-service-fault-family"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']

_VALID_DASHBOARD_BODY = json.dumps(
    {
        "widgets": [
            {
                "type": "text",
                "x": 0,
                "y": 0,
                "width": 6,
                "height": 3,
                "properties": {"markdown": "# behavioral test dashboard"},
            }
        ]
    }
)

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

@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Metric, anomaly-detector, dashboard and metric-stream lifecycles succeed for well-formed
    input, and their not-found errors are exact client codes, never InternalServiceError (5xx),
    which cannot be triggered on demand."""
    cw = ctx.client("cloudwatch")
    account = ctx.client("sts").get_caller_identity()["Account"]

    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    cw.put_metric_data(MetricData=[{"MetricName": "Healthy", "Value": 1.0}], Namespace=namespace)

    def stats():
        now = datetime.now(timezone.utc)
        return cw.get_metric_statistics(
            Namespace=namespace,
            MetricName="Healthy",
            StartTime=now - timedelta(minutes=5),
            EndTime=now + timedelta(minutes=5),
            Period=60,
            Statistics=["Sum"],
        ).get("Datapoints", [])

    _poll_until(stats, lambda dp: len(dp) > 0, timeout_s=60, interval_s=3)
    listed_metrics = _poll_until(
        lambda: cw.list_metrics(Namespace=namespace, MetricName="Healthy").get("Metrics", []),
        lambda ms: any(m["MetricName"] == "Healthy" for m in ms),
        timeout_s=60,
        interval_s=3,
        description="Healthy metric visible via list_metrics",
    )
    assert any(m["MetricName"] == "Healthy" for m in listed_metrics), (
        f"expected Healthy metric visible via list_metrics in {namespace!r}, got {listed_metrics!r}"
    )

    namespace2 = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    metric_name = "AnomalyMetric"
    cw.put_anomaly_detector(Namespace=namespace2, MetricName=metric_name, Stat="Average")
    detectors = _poll_until(
        lambda: cw.describe_anomaly_detectors(Namespace=namespace2, MetricName=metric_name).get(
            "AnomalyDetectors", []
        ),
        lambda ds: len(ds) > 0,
        timeout_s=30,
        interval_s=2,
    )
    assert len(detectors) == 1, f"expected exactly one anomaly detector, got {detectors!r}"
    cw.delete_anomaly_detector(Namespace=namespace2, MetricName=metric_name, Stat="Average")
    remaining_detectors = _poll_until(
        lambda: cw.describe_anomaly_detectors(Namespace=namespace2, MetricName=metric_name).get(
            "AnomalyDetectors", []
        ),
        lambda ds: len(ds) == 0,
        timeout_s=30,
        interval_s=2,
    )
    assert remaining_detectors == [], f"expected no anomaly detectors after delete, got {remaining_detectors!r}"
    dup_delete_code, dup_delete_message = _err(
        lambda: cw.delete_anomaly_detector(Namespace=namespace2, MetricName=metric_name, Stat="Average")
    )
    assert dup_delete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on double-delete of anomaly detector, got {dup_delete_code}"
    )
    assert dup_delete_message == 'Anomaly detector not found', (
        f"unexpected double-delete message: {dup_delete_message!r}"
    )

    dash_name = ctx.unique_name("sim2real-behav-cwprobe-dash-")
    cw.put_dashboard(DashboardName=dash_name, DashboardBody=_VALID_DASHBOARD_BODY)
    ctx.on_cleanup(lambda _n=dash_name: cw.delete_dashboards(DashboardNames=[_n]))
    dash_entries = cw.list_dashboards(DashboardNamePrefix=dash_name).get("DashboardEntries", [])
    assert any(e["DashboardName"] == dash_name for e in dash_entries), (
        f"expected {dash_name!r} in list_dashboards, got {dash_entries!r}"
    )
    dash_arn = f"arn:aws:cloudwatch::{account}:dashboard/{dash_name}"
    cw.tag_resource(ResourceARN=dash_arn, Tags=[{"Key": "sim2real-behav-cwprobe", "Value": "true"}])
    dash_tags = cw.list_tags_for_resource(ResourceARN=dash_arn).get("Tags", [])
    assert {"Key": "sim2real-behav-cwprobe", "Value": "true"} in dash_tags, (
        f"expected the tag just applied to be visible on {dash_arn!r}, got {dash_tags!r}"
    )
    cw.delete_dashboards(DashboardNames=[dash_name])
    dash_read_code, dash_read_message = _err(lambda: cw.get_dashboard(DashboardName=dash_name))
    assert dash_read_code == "ResourceNotFound", (
        f"expected ResourceNotFound reading a deleted dashboard, got {dash_read_code}"
    )
    assert dash_read_message == f"Dashboard {dash_name} does not exist", (
        f"unexpected message reading a deleted dashboard: {dash_read_message!r}"
    )

    # A metric stream with an unresolved (fabricated) Firehose/role still runs
    # its full lifecycle -- real CloudWatch does not eagerly resolve them.
    stream_name = ctx.unique_name("sim2real-behav-cwprobe-mstream-")
    firehose_arn = f"arn:aws:firehose:{ctx.region}:{account}:deliverystream/{stream_name}"
    role_arn = f"arn:aws:iam::{account}:role/{stream_name}"
    ctx.on_cleanup(lambda _n=stream_name: cw.delete_metric_stream(Name=_n))
    cw.put_metric_stream(
        Name=stream_name,
        FirehoseArn=firehose_arn,
        RoleArn=role_arn,
        OutputFormat="json",
        Tags=[{"Key": "sim2real-behav-cwprobe", "Value": "true"}],
    )

    def stream_state():
        return cw.get_metric_stream(Name=stream_name)["State"]

    _poll_until(stream_state, lambda s: s == "running", timeout_s=30, interval_s=2)
    stream_entries = cw.list_metric_streams().get("Entries", [])
    assert any(e["Name"] == stream_name for e in stream_entries), (
        f"expected {stream_name!r} in list_metric_streams, got {stream_entries!r}"
    )
    cw.stop_metric_streams(Names=[stream_name])
    _poll_until(stream_state, lambda s: s == "stopped", timeout_s=30, interval_s=2)
    cw.start_metric_streams(Names=[stream_name])
    _poll_until(stream_state, lambda s: s == "running", timeout_s=30, interval_s=2)
    cw.delete_metric_stream(Name=stream_name)

    code, message = _err(lambda: cw.get_metric_stream(Name=stream_name))
    assert code == "ResourceNotFoundException", f"expected clean ResourceNotFoundException after delete, got {code}"
    assert message == "", f"unexpected not-found message after delete: {message!r}"
    assert code != "InternalServiceError", "a routine not-found lookup must never surface as InternalServiceError"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
