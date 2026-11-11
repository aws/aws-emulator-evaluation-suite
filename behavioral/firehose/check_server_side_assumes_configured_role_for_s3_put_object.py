"""server-side-assumes-configured-role-for-s3-put-object."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-assumes-configured-role-for-s3-put-object"
GROUP = "server-side"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/APIReference/API_BufferingHints.html
@tags(
    "axis:negative-delivery",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """Firehose's managed S3 delivery path assumes the exact IAM role configured on the
    destination: delivery succeeds while the role's inline policy is present (positive
    control), then stops (record never lands in S3) once that policy is revoked."""
    bucket = _create_bucket(ctx)
    role = _create_firehose_role(ctx, bucket)
    firehose = ctx.client("firehose")
    stream_name = _create_s3_stream(
        ctx, firehose, bucket, role["role_arn"],
        buffering_hints={"SizeInMBs": 1, "IntervalInSeconds": 60},
    )
    _wait_stream_active(ctx, firehose, stream_name)

    s3 = ctx.client("s3")

    marker_ok = ctx.unique_name("marker-before-revoke-")
    firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": f"{marker_ok}\n".encode("utf-8")})
    lines = _poll_until(
        lambda: _collect_s3_lines(s3, bucket),
        lambda ls: any(marker_ok in line for line in ls),
        timeout_s=150.0,
        interval_s=5.0,
    )
    assert any(marker_ok in line for line in lines), "positive control: record never delivered with a valid role"

    # Break exactly one thing: revoke the role's only permission to write to the bucket.
    iam = ctx.client("iam")
    iam.delete_role_policy(RoleName=role["role_name"], PolicyName=role["policy_name"])

    marker_broken = ctx.unique_name("marker-after-revoke-")
    firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": f"{marker_broken}\n".encode("utf-8")})
    end_lines = _poll_until(
        lambda: _collect_s3_lines(s3, bucket),
        lambda ls: any(marker_broken in line for line in ls),
        timeout_s=150.0,
        interval_s=5.0,
    )
    assert not any(marker_broken in line for line in end_lines), (
        "record was delivered to S3 despite the delivery role's S3 permissions being revoked"
    )


def _bucket_arn(name: str) -> str:
    return f"arn:aws:s3:::{name}"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-fh-").lower().replace("_", "-")
    if ctx.region and ctx.region != "us-east-1":
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    else:
        s3.create_bucket(Bucket=name)

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_firehose_role(ctx, bucket_name: str) -> dict:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-fh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    policy_name = "s3-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject",
                "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject",
            ],
            "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return {"role_name": role_name, "role_arn": role_arn, "policy_name": policy_name}


def _create_s3_stream(ctx, firehose, bucket, role_arn, buffering_hints, prefix=None, timeout_s=120.0) -> str:
    name = ctx.unique_name("sim2real-behav-fh-stream-")
    s3_config = {
        "RoleARN": role_arn,
        "BucketARN": _bucket_arn(bucket),
        "BufferingHints": buffering_hints,
    }
    if prefix:
        s3_config["Prefix"] = prefix
    # IAM role trust propagation into Firehose is eventually consistent -- a freshly created
    # role can transiently be rejected with InvalidArgumentException ("unable to assume role")
    # even though the trust policy is correct, so retry through that window instead of sleeping.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            firehose.create_delivery_stream(DeliveryStreamName=name, S3DestinationConfiguration=s3_config)
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if code == "InvalidArgumentException" and "unable to assume role" in msg.lower() and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True))
    return name


def _wait_stream_active(ctx, firehose, name, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status in ("CREATING_FAILED", "DELETING_FAILED"):
            raise AssertionError(f"delivery stream entered {status}: {desc.get('FailureDescription')}")
        time.sleep(3)
    raise AssertionError("delivery stream never became ACTIVE")


def _collect_s3_lines(s3, bucket) -> list[str]:
    keys = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            keys.append(obj["Key"])
    keys.sort()
    lines: list[str] = []
    for key in keys:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        text = body.decode("utf-8", errors="replace")
        lines.extend([line for line in text.split("\n") if line])
    return lines


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
