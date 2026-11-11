"""server-side-enforces-single-active-role-after-update-destination."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "server-side-enforces-single-active-role-after-update-destination"
GROUP = "server-side"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/APIReference/API_BufferingHints.html
@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """After UpdateDestination swaps RoleARN from role A to role B, revoking A's policy does not
    break delivery but revoking B's does: the active role is re-resolved, not cached from
    creation."""
    bucket = _create_bucket(ctx)
    role_a = _create_firehose_role(ctx, bucket, suffix="a")
    role_b = _create_firehose_role(ctx, bucket, suffix="b")
    firehose = ctx.client("firehose")
    stream_name = _create_s3_stream(
        ctx, firehose, bucket, role_a["role_arn"],
        buffering_hints={"SizeInMBs": 1, "IntervalInSeconds": 60},
    )
    desc = _wait_stream_active(ctx, firehose, stream_name)

    s3 = ctx.client("s3")

    # Switch the active role from A to B immediately (before any delivery has been
    # attempted with A) -- the interesting claim under test is which role is *currently*
    # configured drives delivery, not which one was used at creation time.
    destination_id = desc["Destinations"][0]["DestinationId"]
    version_id = desc["VersionId"]
    _with_role_propagation_retry(lambda: firehose.update_destination(
        DeliveryStreamName=stream_name,
        CurrentDeliveryStreamVersionId=version_id,
        DestinationId=destination_id,
        S3DestinationUpdate={"RoleARN": role_b["role_arn"]},
    ))

    iam = ctx.client("iam")
    iam.delete_role_policy(RoleName=role_a["role_name"], PolicyName=role_a["policy_name"])

    marker_b = ctx.unique_name("marker-after-switch-")
    firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": f"{marker_b}\n".encode("utf-8")})
    lines_b = _poll_until(
        lambda: _collect_s3_lines(s3, bucket),
        lambda ls: any(marker_b in line for line in ls),
        timeout_s=100.0,
        interval_s=5.0,
    )
    assert any(marker_b in line for line in lines_b), (
        "delivery failed after switching to role B (with role A revoked), even though "
        "role B still has its policy -- expected the pipeline to re-read the active role"
    )

    iam.delete_role_policy(RoleName=role_b["role_name"], PolicyName=role_b["policy_name"])

    marker_c = ctx.unique_name("marker-both-revoked-")
    firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": f"{marker_c}\n".encode("utf-8")})
    lines_c = _poll_until(
        lambda: _collect_s3_lines(s3, bucket),
        lambda ls: any(marker_c in line for line in ls),
        timeout_s=95.0,
        interval_s=5.0,
    )
    assert not any(marker_c in line for line in lines_c), (
        "record was delivered despite the currently-active role (B) having no S3 permissions"
    )



def _bucket_arn(name: str) -> str:
    return f"arn:aws:s3:::{name}"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-fh-").lower().replace("_", "-")
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint;
    # this is an S3 API quirk independent of which region the check is actually running in.
    if ctx.region and ctx.region != "us-east-1":
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    else:
        s3.create_bucket(Bucket=name)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_firehose_role(ctx, bucket_name: str, suffix: str = "") -> dict:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-behav-fh-role-{suffix}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
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


def _with_role_propagation_retry(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    """Firehose synchronously assumes the delivery role when it is handed one (at stream
    creation, and again at UpdateDestination): a role created moments ago can transiently fail
    that assume with InvalidArgumentException while IAM's write is still propagating. Retry
    through that specific window on a deadline rather than sleeping blind before first use."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = exc.response.get("Error", {}).get("Message", "")
            if code == "InvalidArgumentException" and "assume role" in msg.lower() and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_s3_stream(ctx, firehose, bucket, role_arn, buffering_hints, prefix=None) -> str:
    name = ctx.unique_name("sim2real-behav-fh-stream-")
    s3_config = {
        "RoleARN": role_arn,
        "BucketARN": _bucket_arn(bucket),
        "BufferingHints": buffering_hints,
    }
    if prefix:
        s3_config["Prefix"] = prefix
    _with_role_propagation_retry(lambda: firehose.create_delivery_stream(
        DeliveryStreamName=name,
        S3DestinationConfiguration=s3_config,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    ))
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True))
    return name


def _wait_stream_active(ctx, firehose, name, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status in ("CREATING_FAILED", "DELETING_FAILED"):
            raise AssertionError(f"delivery stream entered {status}: {desc.get('FailureDescription')}")
        time.sleep(2)
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
