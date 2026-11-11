"""e2e-create-put-verify-s3-delete."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "e2e-create-put-verify-s3-delete"
GROUP = "state-machine"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Records sent with PutRecordBatch land in S3 after the buffer flush, and after
    DeleteDeliveryStream the stream leaves ListDeliveryStreams and a further PutRecordBatch is
    rejected."""
    firehose = ctx.client("firehose")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = _create_bucket(ctx, s3)
    role_arn = _create_firehose_role(ctx, iam, bucket)
    stream_name = ctx.unique_name("sim2real-fh-e2e-")

    _create_delivery_stream_with_retry(
        ctx,
        firehose,
        DeliveryStreamName=stream_name,
        DeliveryStreamType="DirectPut",
        S3DestinationConfiguration={
            "RoleARN": role_arn,
            "BucketARN": f"arn:aws:s3:::{bucket}",
            "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
        },
        Tags=[{"Key": "sim2real", "Value": "e2e-create-put-verify-s3-delete"}],
    )
    ctx.on_cleanup(lambda: _delete_stream_safe(firehose, stream_name))

    _wait_stream_active(firehose, stream_name, timeout_s=180)

    marker = ctx.unique_name("e2e-marker-")
    records = [{"Data": f"{marker}-{i}\n".encode("utf-8")} for i in range(5)]
    batch_resp = firehose.put_record_batch(
        DeliveryStreamName=stream_name, Records=records
    )
    assert batch_resp["FailedPutCount"] == 0
    assert len(batch_resp["RequestResponses"]) == 5

    # Firehose retries S3 delivery while the just-attached role policy propagates, so the first
    # object can land several minutes after the 60 s buffer flush.
    objects = _poll_until(
        probe=lambda: _list_matching_objects(s3, bucket, marker),
        predicate=lambda found: len(found) >= 1,
        timeout_s=600,
        interval_s=10,
    )
    assert len(objects) >= 1, "no object matching the batch marker landed in S3"
    body = b"".join(
        s3.get_object(Bucket=bucket, Key=k)["Body"].read() for k in objects
    )
    for i in range(5):
        assert f"{marker}-{i}".encode("utf-8") in body

    firehose.delete_delivery_stream(DeliveryStreamName=stream_name)
    final_status = _poll_until(
        probe=lambda: _stream_exists(firehose, stream_name),
        predicate=lambda exists: exists is False,
        timeout_s=120,
        interval_s=5,
    )
    assert final_status is False, "delivery stream still describable after delete"

    names = firehose.list_delivery_streams()["DeliveryStreamNames"]
    assert stream_name not in names

    try:
        firehose.put_record_batch(DeliveryStreamName=stream_name, Records=records)
        raise AssertionError("PutRecordBatch against a deleted delivery stream unexpectedly succeeded")
    except firehose.exceptions.ResourceNotFoundException as exc:
        account = role_arn.split(":")[4]
        message = exc.response["Error"]["Message"]
        assert message == f"Firehose not found under account {account}.", (
            f"PutRecordBatch against the deleted stream must report it not found, got {message!r}"
        )


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _wait_stream_active(firehose_client, name: str, timeout_s: float = 180) -> None:
    def _status() -> str:
        return firehose_client.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"]

    final = _poll_until(_status, lambda s: s != "CREATING", timeout_s=timeout_s, interval_s=5)
    assert final == "ACTIVE", f"delivery stream did not become ACTIVE, ended in {final}"


def _stream_exists(firehose_client, name: str) -> bool:
    try:
        firehose_client.describe_delivery_stream(DeliveryStreamName=name)
        return True
    except firehose_client.exceptions.ResourceNotFoundException:
        return False


#: Bound for a deleted delivery stream to answer not-found, inside the suite's cleanup budget.
_STREAM_DELETE_S = 300.0


def _delete_stream_safe(firehose_client, name: str) -> None:
    """Delete the stream, retrying while it is still CREATING, and poll every 2 s until it is not found."""
    deadline = time.monotonic() + _STREAM_DELETE_S
    deleted = False
    while True:
        status = None
        try:
            if not deleted:
                firehose_client.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
                deleted = True
            status = firehose_client.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"][
                "DeliveryStreamStatus"
            ]
        except firehose_client.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException":
                raise
        if status == "DELETING_FAILED":
            raise AssertionError(f"delivery stream {name} entered DELETING_FAILED")
        if time.monotonic() >= deadline:
            raise AssertionError(f"delivery stream {name} still present {_STREAM_DELETE_S:.0f} s after DeleteDeliveryStream")
        time.sleep(2)


def _create_delivery_stream_with_retry(ctx, firehose_client, **kwargs) -> None:
    # A just-created IAM role can take a few seconds to become visible/assumable
    # by the Firehose service; retry InvalidArgumentException for a bounded window.
    deadline = time.monotonic() + 90
    while True:
        try:
            firehose_client.create_delivery_stream(**kwargs)
            return
        except firehose_client.exceptions.InvalidArgumentException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _list_matching_objects(s3_client, bucket: str, marker: str) -> list[str]:
    keys: list[str] = []
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            keys.append(obj["Key"])
    matched = []
    for key in keys:
        body = s3_client.get_object(Bucket=bucket, Key=key)["Body"].read()
        if marker.encode("utf-8") in body:
            matched.append(key)
    return matched


def _create_bucket(ctx, s3_client) -> str:
    bucket = ctx.unique_name("sim2real-fh-e2e-").lower()
    if ctx.region == "us-east-1":
        # CreateBucketConfiguration/LocationConstraint is rejected for us-east-1 itself.
        s3_client.create_bucket(Bucket=bucket)
    else:
        s3_client.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3_client.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "e2e-create-put-verify-s3-delete"}]},
    )

    def _teardown() -> None:
        paginator = s3_client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3_client.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3_client.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_teardown)
    return bucket


def _create_firehose_role(ctx, iam_client, bucket: str) -> str:
    role_name = ctx.unique_name("sim2real-fh-e2e-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "firehose.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "e2e-create-put-verify-s3-delete"}],
    )["Role"]
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
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    policy_name = "s3-access"
    iam_client.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )

    def _teardown() -> None:
        iam_client.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam_client.delete_role(RoleName=role_name)

    ctx.on_cleanup(_teardown)
    return role["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
