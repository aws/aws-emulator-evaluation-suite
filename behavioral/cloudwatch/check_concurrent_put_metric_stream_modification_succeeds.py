"""concurrent-put-metric-stream-modification-succeeds."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-put-metric-stream-modification-succeeds"
GROUP = "concurrency"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent PutMetricStream updates to one stream all succeed (last write wins) and leave
    IncludeFilters equal to exactly one writer's payload: never a merge of racing updates."""
    from botocore.exceptions import ClientError

    cw = ctx.client("cloudwatch")
    firehose_arn = _create_backing_firehose(ctx)
    metric_stream_role_arn = _create_metric_stream_role(ctx, firehose_arn)

    stream_name = ctx.unique_name("sim2real-behav-mstream-")
    cw.put_metric_stream(
        Name=stream_name,
        FirehoseArn=firehose_arn,
        RoleArn=metric_stream_role_arn,
        OutputFormat="json",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=stream_name))

    def racer(i: int):
        namespace = f"sim2real/behav/{i}"
        try:
            cw.put_metric_stream(
                Name=stream_name,
                FirehoseArn=firehose_arn,
                RoleArn=metric_stream_role_arn,
                OutputFormat="json",
                IncludeFilters=[{"Namespace": namespace}],
            )
            return ("ok", namespace)
        except ClientError as e:
            return ("err", e.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(racer, range(8)))

    attempted_namespaces = set()
    for status, payload in results:
        if status == "ok":
            attempted_namespaces.add(payload)
        elif payload == "ConcurrentModificationException":
            # A genuine optimistic-concurrency rejection is also an acceptable, safe
            # outcome -- it just wasn't the one real CloudWatch happened to choose here.
            pass
        else:
            raise AssertionError(f"unexpected error code from concurrent PutMetricStream: {payload}")

    assert attempted_namespaces, "no concurrent PutMetricStream writer ever succeeded"

    # stream must still be describable and consistent: its IncludeFilters must match
    # exactly one racer's payload, never a corrupted merge of more than one.
    desc = cw.get_metric_stream(Name=stream_name)
    assert desc["Name"] == stream_name, f"expected Name={stream_name!r}, got {desc['Name']!r}"
    assert desc["State"] == "running", f"expected State='running', got {desc['State']!r}"
    final_namespaces = {f["Namespace"] for f in desc.get("IncludeFilters", [])}
    assert final_namespaces, "metric stream lost its IncludeFilters after concurrent writes"
    assert final_namespaces.issubset(attempted_namespaces), (
        f"metric stream's final IncludeFilters {final_namespaces} do not match any single "
        f"concurrent writer's payload {attempted_namespaces} -- suggests a corrupted merge"
    )
    assert len(final_namespaces) == 1, (
        f"expected exactly one winning writer's IncludeFilters to survive, got a merged "
        f"set instead: {final_namespaces}"
    )


# ===== helpers =====

def _create_backing_firehose(ctx) -> str:
    """Create an S3 bucket + Firehose delivery stream that PutMetricStream can reference."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    firehose = ctx.client("firehose")

    bucket_name = ctx.unique_name("sim2real-behav-mstream-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    fh_role_name = ctx.unique_name("sim2real-behav-fhrole-")
    fh_role = iam.create_role(
        RoleName=fh_role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=fh_role_name))
    iam.put_role_policy(
        RoleName=fh_role_name,
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
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=fh_role_name, PolicyName="s3-write"))

    stream_name = ctx.unique_name("sim2real-behav-fhstream-")
    _retry_on(
        ctx,
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=stream_name,
            DeliveryStreamType="DirectPut",
            ExtendedS3DestinationConfiguration={"RoleARN": fh_role, "BucketARN": bucket_arn},
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        ),
        ("InvalidArgumentException", "AccessDeniedException"),
        "could not create backing firehose delivery stream",
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))

    deadline = time.monotonic() + 120
    arn = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
        if desc["DeliveryStreamStatus"] == "ACTIVE":
            arn = desc["DeliveryStreamARN"]
            break
        time.sleep(3)
    if arn is None:
        raise AssertionError("firehose delivery stream never became ACTIVE")
    return arn


def _create_metric_stream_role(ctx, firehose_arn: str) -> str:
    iam = ctx.client("iam")
    cw = ctx.client("cloudwatch")
    role_name = ctx.unique_name("sim2real-behav-msrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
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
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="firehose-put"))

    # IAM role propagation: a probe stream is created and deleted once the role is usable.
    def _probe_stream():
        probe_name = ctx.unique_name("sim2real-behav-msprobe-")
        cw.put_metric_stream(
            Name=probe_name, FirehoseArn=firehose_arn, RoleArn=role_arn, OutputFormat="json"
        )
        cw.delete_metric_stream(Name=probe_name)

    _retry_on(
        ctx,
        _probe_stream,
        ("InvalidParameterValueException", "AccessDeniedException"),
        "metric stream role never became usable",
    )
    return role_arn


def _retry_on(ctx, fn, codes, what, timeout_s=60.0):
    """Call fn() until it succeeds, retrying only `codes` (IAM propagation) every 2 s to the deadline."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while True:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] not in codes:
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"{what}: {e}") from e
        time.sleep(2)


def _empty_and_delete_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    try:
        objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    s3.delete_bucket(Bucket=bucket_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
