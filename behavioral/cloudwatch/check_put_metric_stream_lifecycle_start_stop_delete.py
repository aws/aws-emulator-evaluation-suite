"""put-metric-stream-lifecycle-start-stop-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-stream-lifecycle-start-stop-delete"
GROUP = 'metric-streams'
SERVICES = ['cloudwatch']

def _err(fn):
    """Call fn(); return the botocore Error dict if a ClientError is raised. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

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

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutMetricStream accepts an unresolved Firehose/role pair, and the stream moves running ->
    stopped -> running, echoing its FirehoseArn, until DeleteMetricStream leaves GetMetricStream
    answering ResourceNotFoundException with the exact message."""
    cw = ctx.client("cloudwatch")
    _acct = ctx.client("sts").get_caller_identity()["Account"]
    stream_name = ctx.unique_name("sim2real-behav-cwprobe-stream-")
    account = _acct
    firehose_arn = f"arn:aws:firehose:{ctx.region}:{account}:deliverystream/{stream_name}"
    role_arn = f"arn:aws:iam::{account}:role/{stream_name}"
    ctx.on_cleanup(lambda _n=stream_name: cw.delete_metric_stream(Name=_n))

    try:
        cw.put_metric_stream(
            Name=stream_name,
            FirehoseArn=firehose_arn,
            RoleArn=role_arn,
            OutputFormat="json",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    except ClientError as exc:
        raise AssertionError(
            f"expected PutMetricStream to accept an unresolved Firehose/role, got error {exc.response['Error']!r}"
        ) from exc

    def probe():
        return cw.get_metric_stream(Name=stream_name)

    resp = _poll_until(probe, lambda r: r.get("State") is not None, timeout_s=30, interval_s=2)
    assert resp["State"] == "running", f"expected a new metric stream to start running, got {resp['State']}"
    assert resp["FirehoseArn"] == firehose_arn, "GetMetricStream must echo back the configured FirehoseArn"

    cw.stop_metric_streams(Names=[stream_name])
    resp = _poll_until(probe, lambda r: r.get("State") == "stopped", timeout_s=30, interval_s=2)
    assert resp["State"] == "stopped", f"expected 'stopped' after StopMetricStreams, got {resp['State']!r}"

    cw.start_metric_streams(Names=[stream_name])
    resp = _poll_until(probe, lambda r: r.get("State") == "running", timeout_s=30, interval_s=2)
    assert resp["State"] == "running", f"expected 'running' after StartMetricStreams, got {resp['State']!r}"

    cw.delete_metric_stream(Name=stream_name)

    def get_op():
        return cw.get_metric_stream(Name=stream_name)

    del_err = _err(get_op)
    assert del_err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {del_err!r}"
    )
    expected = ""
    assert del_err.get("Message", "") == expected, f"expected {expected!r}, got {del_err.get('Message', '')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
