"""put-record-on-kinesis-source-stream-rejected."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "put-record-on-kinesis-source-stream-rejected"
GROUP = "overly-permissive"
SERVICES = ["firehose"]

# Post-delivery absence hold: 5 samples 2 s apart, a fixed 10 s.
_HOLD_SAMPLES = 5
_HOLD_INTERVAL_S = 2.0


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRecord on a KinesisStreamAsSource stream is rejected with InvalidArgumentException and the
    record never lands in S3, while a sibling DirectPut stream fed after it delivers; the rejected
    marker stays absent through the control's delivery and a fixed hold after it."""
    firehose = ctx.client("firehose")
    ctx.client("s3")

    bucket_name = _create_bucket(ctx)
    kinesis_stream_arn = _create_kinesis_stream(ctx)
    role_arn = _create_firehose_role(ctx, bucket_name, kinesis_stream_arn)

    kinesis_source_stream = ctx.unique_name("sim2real-behav-fhksrc-")
    _create_kinesis_source_delivery_stream(ctx, kinesis_source_stream, role_arn, kinesis_stream_arn, bucket_name)
    ctx.on_cleanup(lambda: _delete_stream_if_exists(ctx, kinesis_source_stream))
    _wait_stream_active(ctx, kinesis_source_stream)

    direct_put_stream = ctx.unique_name("sim2real-behav-fhdirect-")
    _create_delivery_stream_with_retry(ctx, direct_put_stream, role_arn, bucket_name)
    ctx.on_cleanup(lambda: _delete_stream_if_exists(ctx, direct_put_stream))
    _wait_stream_active(ctx, direct_put_stream)

    rejected_marker = str(uuid.uuid4())
    code, message = _error_code(
        lambda: firehose.put_record(
            DeliveryStreamName=kinesis_source_stream,
            Record={"Data": json.dumps({"marker": rejected_marker}).encode("utf-8")},
        )
    )
    assert code == "InvalidArgumentException", f"expected InvalidArgumentException, got {code}"
    assert message == "This operation is not permitted on KinesisStreamAsSource delivery stream type.", (
        f"unexpected refusal message {message!r}"
    )

    # Twin DirectPut control on the same role and bucket: its delivery proves the observation
    # window can catch a real write, and it is put after the rejected record, so by its arrival
    # the rejected one has had at least as long to land.
    accepted_marker = str(uuid.uuid4())
    t0 = time.monotonic()
    resp = firehose.put_record(
        DeliveryStreamName=direct_put_stream,
        Record={"Data": json.dumps({"marker": accepted_marker}).encode("utf-8")},
    )
    assert "RecordId" in resp, f"expected a RecordId in the DirectPut PutRecord response, got {resp!r}"

    delivered = False
    deadline = t0 + _budget_s(ctx, 180.0)
    while time.monotonic() < deadline:
        assert not _marker_present(ctx, bucket_name, rejected_marker), (
            f"marker {rejected_marker!r} appeared in S3 {time.monotonic() - t0:.0f}s after PutRecord "
            f"was rejected with InvalidArgumentException"
        )
        if _marker_present(ctx, bucket_name, accepted_marker):
            delivered = True
            break
        time.sleep(1)
    if not delivered and _budget_spent(ctx):
        raise TimeoutError(f"positive control marker {accepted_marker!r} landing in S3: the run budget ended first; not graded")
    assert delivered, (
        f"positive control marker {accepted_marker!r} never landed in S3 within "
        f"{time.monotonic() - t0:.0f}s"
    )

    # A fixed hold after the control's delivery, so a target that delivers the rejected record
    # on its own stream a little later than the accepted one is still caught.
    for _ in range(_HOLD_SAMPLES):
        time.sleep(_HOLD_INTERVAL_S)
        assert not _marker_present(ctx, bucket_name, rejected_marker), (
            f"marker {rejected_marker!r} appeared in S3 during the post-delivery hold window"
        )



def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-behav-fh-")
    kwargs = {"Bucket": bucket_name}
    # Not a region pin on the resource: S3 rejects an explicit LocationConstraint of
    # us-east-1 itself, so the literal here names S3's own quirk, not a fixed region.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket_name))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})
    return bucket_name


def _delete_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objects:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket_name)


def _create_kinesis_stream(ctx, timeout_s: float = 120.0) -> str:
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-fhkstream-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True))
    kinesis.add_tags_to_stream(StreamName=stream_name, Tags={"simparity-check": CHECK})

    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"kinesis stream {stream_name} becoming ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"kinesis stream {stream_name} never became ACTIVE")


def _create_firehose_role(ctx, bucket_name: str, kinesis_stream_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-fhrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "firehose-access"
    policy_doc = {
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
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "kinesis:DescribeStream",
                    "kinesis:GetShardIterator",
                    "kinesis:GetRecords",
                    "kinesis:ListShards",
                ],
                "Resource": kinesis_stream_arn,
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_kinesis_source_delivery_stream(
    ctx, stream_name: str, role_arn: str, kinesis_stream_arn: str, bucket_name: str, timeout_s: float = 90.0
) -> None:
    firehose = ctx.client("firehose")
    dest = {
        "RoleARN": role_arn,
        "BucketARN": f"arn:aws:s3:::{bucket_name}",
        "BufferingHints": {"IntervalInSeconds": 0, "SizeInMBs": 1},
    }
    source = {"KinesisStreamARN": kinesis_stream_arn, "RoleARN": role_arn}
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_err = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=stream_name,
                DeliveryStreamType="KinesisStreamAsSource",
                KinesisStreamSourceConfiguration=source,
                ExtendedS3DestinationConfiguration=dest,
                Tags=[{"Key": "simparity-check", "Value": CHECK}],
            )
            return
        except firehose.exceptions.InvalidArgumentException as exc:
            last_err = exc
            time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"CreateDeliveryStream {stream_name} past IAM propagation: the run budget ended first; not graded")
    raise AssertionError(f"CreateDeliveryStream kept failing on IAM propagation: {last_err}")


def _create_delivery_stream_with_retry(
    ctx, stream_name: str, role_arn: str, bucket_name: str, timeout_s: float = 90.0
) -> None:
    firehose = ctx.client("firehose")
    dest = {
        "RoleARN": role_arn,
        "BucketARN": f"arn:aws:s3:::{bucket_name}",
        "BufferingHints": {"IntervalInSeconds": 0, "SizeInMBs": 1},
    }
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_err = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=stream_name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=dest,
                Tags=[{"Key": "simparity-check", "Value": CHECK}],
            )
            return
        except firehose.exceptions.InvalidArgumentException as exc:
            last_err = exc
            time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"CreateDeliveryStream {stream_name} past IAM propagation: the run budget ended first; not graded")
    raise AssertionError(f"CreateDeliveryStream kept failing on IAM propagation: {last_err}")


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 120.0) -> None:
    firehose = ctx.client("firehose")

    def probe():
        return firehose.describe_delivery_stream(DeliveryStreamName=stream_name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"]

    status = _poll_until(
        probe, lambda s: s in ("ACTIVE", "CREATING_FAILED"), timeout_s=_budget_s(ctx, timeout_s), interval_s=1.0
    )
    if status not in ("ACTIVE", "CREATING_FAILED") and _budget_spent(ctx):
        raise TimeoutError(f"stream {stream_name} becoming ACTIVE: the run budget ended first; not graded")
    assert status == "ACTIVE", f"stream {stream_name} ended in status {status}"


def _delete_stream_if_exists(ctx, stream_name: str) -> None:
    firehose = ctx.client("firehose")
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=stream_name)
    except firehose.exceptions.ResourceNotFoundException:
        pass


def _marker_present(ctx, bucket_name: str, marker: str) -> bool:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket_name)
    for obj in resp.get("Contents", []):
        body = s3.get_object(Bucket=bucket_name, Key=obj["Key"])["Body"].read()
        if marker.encode("utf-8") in body:
            return True
    return False


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
