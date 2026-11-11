"""e2e-create-put-flush-verify-delete-preserves-s3-objects."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-create-put-flush-verify-delete-preserves-s3-objects"
GROUP = "e2e"
SERVICES = ["firehose"]

_MANAGED_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A full create -> PutRecordBatch -> flush -> delete flow: the exact records land in
    S3, and deleting the delivery stream is a control-plane act that leaves the
    already-delivered S3 objects completely untouched."""
    firehose = ctx.client("firehose")
    s3 = ctx.client("s3")

    bucket_name = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket_name)
    stream_name = ctx.unique_name("sim2real-behav-fhstream-")

    _create_delivery_stream_with_retry(ctx, stream_name, role_arn, bucket_name)
    ctx.on_cleanup(lambda: _delete_stream_if_exists(ctx, stream_name))
    _wait_stream_active(ctx, stream_name)

    markers = [str(uuid.uuid4()) for _ in range(5)]
    records = [{"Data": json.dumps({"marker": m, "i": i}).encode("utf-8")} for i, m in enumerate(markers)]
    resp = firehose.put_record_batch(DeliveryStreamName=stream_name, Records=records)
    assert resp["FailedPutCount"] == 0, f"unexpected failed puts: {resp}"

    delivered_keys = _poll_until(
        lambda: _keys_containing_all_markers(ctx, bucket_name, markers),
        lambda keys: keys is not None,
        timeout_s=180.0,
        interval_s=10.0,
    )
    assert delivered_keys, f"markers {markers} never fully landed in bucket {bucket_name}"

    # Snapshot exact object set + contents before deleting the stream.
    snapshot = {}
    for key in delivered_keys:
        snapshot[key] = s3.get_object(Bucket=bucket_name, Key=key)["Body"].read()

    firehose.delete_delivery_stream(DeliveryStreamName=stream_name)
    _wait_stream_gone(ctx, stream_name)

    # The consequence of deletion: the already-delivered objects are byte-for-byte intact.
    for key, content in snapshot.items():
        current = s3.get_object(Bucket=bucket_name, Key=key)["Body"].read()
        assert current == content, f"object {key} content changed after stream deletion"
    current_keys = {o["Key"] for o in s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])}
    assert set(snapshot.keys()) <= current_keys, "delivered objects disappeared after stream deletion"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-behav-fh-")
    kwargs = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        # us-east-1 is the one region where CreateBucket rejects an explicit
        # LocationConstraint; every other region requires it.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket_name))
    try:
        s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": _MANAGED_TAGS})
    except ClientError:
        pass
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


def _create_firehose_role(ctx, bucket_name: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-fhrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=_MANAGED_TAGS
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "firehose-s3-access"
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
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_delivery_stream_with_retry(
    ctx, stream_name: str, role_arn: str, bucket_name: str, timeout_s: float = 90.0
) -> None:
    firehose = ctx.client("firehose")
    dest = {
        "RoleARN": role_arn,
        "BucketARN": f"arn:aws:s3:::{bucket_name}",
        "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
    }
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=stream_name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=dest,
                Tags=_MANAGED_TAGS,
            )
            return
        except firehose.exceptions.InvalidArgumentException as exc:
            # IAM role trust/permissions can take a few seconds to propagate.
            last_err = exc
            time.sleep(5)
    raise AssertionError(f"CreateDeliveryStream kept failing on IAM propagation: {last_err}")


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 120.0) -> None:
    firehose = ctx.client("firehose")

    def probe():
        return firehose.describe_delivery_stream(DeliveryStreamName=stream_name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"]

    status = _poll_until(probe, lambda s: s in ("ACTIVE", "CREATING_FAILED"), timeout_s=timeout_s, interval_s=5.0)
    assert status == "ACTIVE", f"stream {stream_name} ended in status {status}"


def _wait_stream_gone(ctx, stream_name: str, timeout_s: float = 180.0) -> None:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            firehose.describe_delivery_stream(DeliveryStreamName=stream_name)
        except firehose.exceptions.ResourceNotFoundException:
            return
        time.sleep(5)
    raise AssertionError(f"stream {stream_name} was not fully deleted within {timeout_s}s")


def _delete_stream_if_exists(ctx, stream_name: str) -> None:
    firehose = ctx.client("firehose")
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=stream_name)
    except firehose.exceptions.ResourceNotFoundException:
        pass


def _keys_containing_all_markers(ctx, bucket_name: str, markers: list[str]):
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket_name)
    contents = resp.get("Contents", [])
    if not contents:
        return None
    found_keys = []
    remaining = set(markers)
    for obj in contents:
        key = obj["Key"]
        body = s3.get_object(Bucket=bucket_name, Key=key)["Body"].read()
        text = body.decode("utf-8", errors="ignore")
        hit = False
        for m in list(remaining):
            if m in text:
                remaining.discard(m)
                hit = True
        if hit:
            found_keys.append(key)
    if remaining:
        return None
    return found_keys


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
