"""e2e-metric-stream-firehose-data-flow-and-teardown."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-metric-stream-firehose-data-flow-and-teardown"
GROUP = "e2e"
SERVICES = ["cloudwatch"]

_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A metric stream wired to a Firehose delivery stream is observed through GetMetricStream as
    running, stopped, restarted (fed live PutMetricData) and stopped again; once deleted,
    GetMetricStream fails with ResourceNotFoundException."""
    cw = ctx.client("cloudwatch")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")

    bucket_name = ctx.unique_name("sim2real-cwms-bucket-").lower()
    if ctx.region == "us-east-1":
        # us-east-1 is a genuine S3 CreateBucket quirk: it rejects a LocationConstraint.
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": _TAGS})
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    firehose_role_name = ctx.unique_name("sim2real-cwms-fh-role-")
    firehose_role_arn = iam.create_role(
        RoleName=firehose_role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "firehose.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=_TAGS,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: iam.delete_role(RoleName=firehose_role_name)))
    iam.put_role_policy(
        RoleName=firehose_role_name,
        PolicyName="s3-write",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"],
                        "Resource": [bucket_arn, f"{bucket_arn}/*"],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _safe_call(lambda: iam.delete_role_policy(RoleName=firehose_role_name, PolicyName="s3-write"))
    )

    stream_name = ctx.unique_name("sim2real-cwms-fh-")
    delivery_stream_arn = _create_delivery_stream(ctx, firehose, stream_name, firehose_role_arn, bucket_arn)

    metric_stream_role_name = ctx.unique_name("sim2real-cwms-ms-role-")
    metric_stream_role_arn = iam.create_role(
        RoleName=metric_stream_role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "streams.metrics.cloudwatch.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=_TAGS,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: iam.delete_role(RoleName=metric_stream_role_name)))
    iam.put_role_policy(
        RoleName=metric_stream_role_name,
        PolicyName="firehose-write",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                        "Resource": delivery_stream_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: iam.delete_role_policy(RoleName=metric_stream_role_name, PolicyName="firehose-write")
        )
    )

    metric_stream_name = ctx.unique_name("sim2real-cwms-stream-")
    namespace = ctx.unique_name("Sim2Real/MetricStream-")

    def _create_stream():
        cw.put_metric_stream(
            Name=metric_stream_name,
            FirehoseArn=delivery_stream_arn,
            RoleArn=metric_stream_role_arn,
            OutputFormat="json",
            IncludeFilters=[{"Namespace": namespace}],
            Tags=_TAGS,
        )

    _retry_until_role_usable(_create_stream)
    ctx.on_cleanup(lambda: _safe_call(lambda: cw.delete_metric_stream(Name=metric_stream_name)))

    # A newly created metric stream starts running without needing StartMetricStreams.
    state = cw.get_metric_stream(Name=metric_stream_name)["State"]
    assert state == "running", f"expected a freshly created metric stream to start 'running', got {state!r}"

    cw.stop_metric_streams(Names=[metric_stream_name])
    stopped_state = _poll_until(
        lambda: cw.get_metric_stream(Name=metric_stream_name)["State"],
        lambda s: s == "stopped",
        timeout_s=60,
        interval_s=2,
    )
    assert stopped_state == "stopped", f"expected 'stopped' after StopMetricStreams, got {stopped_state!r}"

    cw.start_metric_streams(Names=[metric_stream_name])
    running_state = _poll_until(
        lambda: cw.get_metric_stream(Name=metric_stream_name)["State"],
        lambda s: s == "running",
        timeout_s=60,
        interval_s=2,
    )
    assert running_state == "running", f"expected 'running' after StartMetricStreams, got {running_state!r}"

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": "ThroughputTest", "Value": 42.0, "Unit": "Count"}],
    )

    cw.stop_metric_streams(Names=[metric_stream_name])
    final_state = _poll_until(
        lambda: cw.get_metric_stream(Name=metric_stream_name)["State"],
        lambda s: s == "stopped",
        timeout_s=60,
        interval_s=2,
    )
    assert final_state == "stopped", f"expected 'stopped' after the second StopMetricStreams, got {final_state!r}"

    cw.delete_metric_stream(Name=metric_stream_name)
    code, message = _error(lambda: cw.get_metric_stream(Name=metric_stream_name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a deleted metric stream, got {code!r}"
    )
    # GetMetricStream answers not-found with an empty message.
    assert message == "", f"unexpected GetMetricStream message {message!r}"

    firehose.delete_delivery_stream(DeliveryStreamName=stream_name)
    fh_delete_code = _poll_until_not_found(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=stream_name),
        timeout_s=300,
        interval_s=10,
    )
    assert fh_delete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a deleted delivery stream, got {fh_delete_code!r}"
    )


# ===== helpers =====
def _safe_call(fn):
    """Run a teardown delete; only an already-deleted resource (IAM or Firehose not-found) is tolerated."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met, last observed value: {last!r}")


def _poll_until_not_found(fn, *, timeout_s=180.0, interval_s=5.0):
    """DeleteDeliveryStream is asynchronous: DescribeDeliveryStream keeps succeeding with status
    DELETING for a while afterward, unlike CloudWatch's synchronous DeleteMetricStream. Poll until
    the describe call itself starts raising ResourceNotFoundException; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            desc = fn()["DeliveryStreamDescription"]
            last_status = desc["DeliveryStreamStatus"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return code
            raise
        time.sleep(interval_s)
    raise AssertionError(f"delivery stream still describable after {timeout_s}s, last status={last_status!r}")


def _retry_until_role_usable(fn, *, timeout_s=90.0, interval_s=5.0):
    """IAM role trust/permission propagation can lag a few seconds behind
    CreateRole/PutRolePolicy; retry PutMetricStream until it stops rejecting
    the freshly created RoleArn."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            fn()
            return
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"PutMetricStream never accepted the new role: {last_exc}")


def _create_delivery_stream(ctx, firehose, name, role_arn, bucket_arn):
    def _create():
        firehose.create_delivery_stream(
            DeliveryStreamName=name,
            DeliveryStreamType="DirectPut",
            S3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": bucket_arn},
            Tags=_TAGS,
        )

    # IAM role trust-policy propagation can lag a few seconds behind
    # CreateRole; retry CreateDeliveryStream until Firehose stops rejecting
    # the freshly created role with "unable to assume role".
    _retry_until_role_usable(_create)
    ctx.on_cleanup(lambda: _safe_call(lambda: firehose.delete_delivery_stream(DeliveryStreamName=name)))
    arn = _poll_until(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"],
        lambda desc: desc["DeliveryStreamStatus"] == "ACTIVE",
        timeout_s=90,
        interval_s=3,
    )["DeliveryStreamARN"]
    return arn



def _empty_and_delete_bucket(s3, bucket_name):
    try:
        objects = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        for obj in objects:
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
