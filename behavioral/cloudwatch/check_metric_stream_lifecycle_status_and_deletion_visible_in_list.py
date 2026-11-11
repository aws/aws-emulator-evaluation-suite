"""metric-stream-lifecycle-status-and-deletion-visible-in-list."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "metric-stream-lifecycle-status-and-deletion-visible-in-list"
GROUP = "telemetry"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListMetricStreams reflects a metric stream's running/stopped state within seconds of
    Start/StopMetricStreams, and stops listing the stream after DeleteMetricStream."""
    cw = ctx.client("cloudwatch")
    firehose = ctx.client("firehose")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    name = ctx.unique_name("sim2real-cwms-").lower()
    bucket_name = f"{name}-dest"
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    firehose_role_name = f"{name}-fh-role"
    iam.create_role(
        RoleName=firehose_role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_policy("firehose.amazonaws.com")),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=firehose_role_name))
    iam.put_role_policy(
        RoleName=firehose_role_name,
        PolicyName="s3-write",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:AbortMultipartUpload",
                            "s3:GetBucketLocation",
                            "s3:GetObject",
                            "s3:ListBucket",
                            "s3:ListBucketMultipartUploads",
                            "s3:PutObject",
                        ],
                        "Resource": [bucket_arn, f"{bucket_arn}/*"],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=firehose_role_name, PolicyName="s3-write"))
    firehose_role_arn = iam.get_role(RoleName=firehose_role_name)["Role"]["Arn"]

    def _create_delivery_stream():
        firehose.create_delivery_stream(
            DeliveryStreamName=name,
            DeliveryStreamType="DirectPut",
            S3DestinationConfiguration={"RoleARN": firehose_role_arn, "BucketARN": bucket_arn},
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )

    _retry_until_success(_create_delivery_stream, timeout_s=60.0, interval_s=5.0)
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=name))

    def _delivery_stream_status():
        return firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"]

    _poll_until(_delivery_stream_status, lambda s: s == "ACTIVE", timeout_s=120.0, interval_s=5.0)
    firehose_arn = firehose.describe_delivery_stream(DeliveryStreamName=name)[
        "DeliveryStreamDescription"
    ]["DeliveryStreamARN"]

    cw_role_name = f"{name}-cw-role"
    iam.create_role(
        RoleName=cw_role_name,
        AssumeRolePolicyDocument=json.dumps(
            _trust_policy("streams.metrics.cloudwatch.amazonaws.com")
        ),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=cw_role_name))
    iam.put_role_policy(
        RoleName=cw_role_name,
        PolicyName="firehose-put",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                        "Resource": firehose_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=cw_role_name, PolicyName="firehose-put"))
    cw_role_arn = iam.get_role(RoleName=cw_role_name)["Role"]["Arn"]

    def _create_metric_stream():
        cw.put_metric_stream(
            Name=name,
            FirehoseArn=firehose_arn,
            RoleArn=cw_role_arn,
            OutputFormat="json",
            # Scope to a namespace nothing will ever publish under, so this
            # stream never actually delivers data into the destination bucket.
            IncludeFilters=[{"Namespace": f"{name}-empty-namespace"}],
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )

    # New IAM roles take a short propagation window before CloudWatch can validate them.
    _retry_until_success(_create_metric_stream, timeout_s=60.0, interval_s=5.0)

    metric_stream_deleted = False

    def _cleanup_metric_stream():
        if not metric_stream_deleted:
            cw.delete_metric_stream(Name=name)

    ctx.on_cleanup(_cleanup_metric_stream)

    def _state():
        entries = cw.list_metric_streams().get("Entries", [])
        matches = [e for e in entries if e["Name"] == name]
        return matches[0]["State"] if matches else None

    initial_state = _poll_until(_state, lambda s: s == "running", timeout_s=30.0, interval_s=1.0)
    assert initial_state == "running", (
        f"ListMetricStreams never showed {name!r} as 'running' after PutMetricStream, "
        f"last seen state={initial_state!r}"
    )

    cw.stop_metric_streams(Names=[name])
    stopped_state = _poll_until(_state, lambda s: s == "stopped", timeout_s=10.0, interval_s=0.5)
    assert stopped_state == "stopped", (
        f"ListMetricStreams never showed {name!r} as 'stopped' after StopMetricStreams, "
        f"last seen state={stopped_state!r}"
    )

    cw.start_metric_streams(Names=[name])
    restarted_state = _poll_until(_state, lambda s: s == "running", timeout_s=10.0, interval_s=0.5)
    assert restarted_state == "running", (
        f"ListMetricStreams never showed {name!r} back as 'running' after StartMetricStreams, "
        f"last seen state={restarted_state!r}"
    )

    cw.delete_metric_stream(Name=name)
    metric_stream_deleted = True
    final_state = _poll_until(_state, lambda s: s is None, timeout_s=30.0, interval_s=1.0)
    assert final_state is None, (
        f"ListMetricStreams still listed {name!r} after DeleteMetricStream, "
        f"last seen state={final_state!r}"
    )


def _trust_policy(principal_service):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": principal_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _retry_until_success(fn, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001 - transient IAM propagation
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"operation never succeeded within {timeout_s}s: {last_exc!r}")


def _empty_and_delete_bucket(s3, bucket_name):
    try:
        objects = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        for obj in objects:
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
    finally:
        s3.delete_bucket(Bucket=bucket_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
