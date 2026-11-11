"""put-record-binary-blob-byte-equality."""
from __future__ import annotations

import json
import os
import time

from behavioral_harness import tags

CHECK = "put-record-binary-blob-byte-equality"
GROUP = "representation"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A raw non-UTF8 binary blob sent via PutRecord is delivered to S3 with exact byte equality."""
    # Non-UTF8 bytes: every byte value 0-255 plus an invalid UTF-8 continuation sequence,
    # plus random bytes to rule out any base64/text re-encoding loss.
    payload = bytes(range(256)) + b"\xff\xfe\x00\x01\xc0\xc1" + os.urandom(2048)

    setup = _create_firehose_role_and_bucket(ctx)
    fh = ctx.client("firehose")
    stream_name = ctx.unique_name("sim2real-fh-bin-")
    s3_config = {
        "RoleARN": setup["role_arn"],
        "BucketARN": f"arn:aws:s3:::{setup['bucket']}",
        "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
    }
    _create_delivery_stream_with_retry(ctx, fh, stream_name, s3_config)
    ctx.on_cleanup(lambda: fh.delete_delivery_stream(DeliveryStreamName=stream_name))
    _wait_active(ctx, fh, stream_name)

    resp = fh.put_record(DeliveryStreamName=stream_name, Record={"Data": payload})
    assert resp.get("RecordId"), f"PutRecord must return a RecordId, got {resp!r}"

    objects = _poll_for_objects(ctx, setup["bucket"], min_count=1, timeout_s=240)
    assert len(objects) == 1, f"expected exactly 1 delivered object, got {len(objects)}"
    body = _get_object_bytes(ctx, setup["bucket"], objects[0]["Key"])
    assert body == payload, "delivered S3 object bytes do not exactly match the original binary blob"


def _role_trust_policy() -> str:
    return json.dumps(
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
    )


def _create_firehose_role_and_bucket(ctx) -> dict:
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-fh-").lower().replace("_", "-")
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    role_name = ctx.unique_name("sim2real-fh-role-")
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_role_trust_policy()
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = json.dumps(
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
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                }
            ],
        }
    )
    policy_name = ctx.unique_name("sim2real-fh-policy-")
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_doc
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return {"bucket": bucket, "role_arn": role["Arn"]}


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_delivery_stream_with_retry(
    ctx, fh, name: str, s3_config: dict, delivery_stream_type: str = "DirectPut"
) -> None:
    from botocore.exceptions import ClientError

    kwargs = {
        "DeliveryStreamName": name,
        "DeliveryStreamType": delivery_stream_type,
        "ExtendedS3DestinationConfiguration": s3_config,
    }
    deadline = time.monotonic() + 90
    last_err = None
    while time.monotonic() < deadline:
        try:
            fh.create_delivery_stream(**kwargs)
            return
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidArgumentException":
                time.sleep(5)
                continue
            raise
    raise last_err


def _wait_active(ctx, fh, name: str, timeout_s: int = 180) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = fh.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status.endswith("FAILED"):
            raise AssertionError(f"stream entered failed state: {status}")
        time.sleep(5)
    raise AssertionError(f"stream {name} did not become ACTIVE within {timeout_s}s")


def _list_objects(ctx, bucket: str, prefix: str = "") -> list:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    return resp.get("Contents", [])


def _get_object_bytes(ctx, bucket: str, key: str) -> bytes:
    s3 = ctx.client("s3")
    return s3.get_object(Bucket=bucket, Key=key)["Body"].read()


def _poll_for_objects(
    ctx, bucket: str, min_count: int = 1, timeout_s: int = 240, interval_s: int = 10
) -> list:
    deadline = time.monotonic() + timeout_s
    objs: list = []
    while time.monotonic() < deadline:
        objs = _list_objects(ctx, bucket)
        if len(objs) >= min_count:
            return objs
        time.sleep(interval_s)
    raise AssertionError(
        f"expected >= {min_count} objects in {bucket} within {timeout_s}s, got {len(objs)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
