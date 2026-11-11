"""s3-delivery-triggered-by-buffer-interval-timeout."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-delivery-triggered-by-buffer-interval-timeout"
GROUP = "visibility-timeout-ttl"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/APIReference/API_BufferingHints.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A small record stays undelivered until BufferingHints.IntervalInSeconds elapses,
    then flushes to S3 -- delivery timing driven by the interval, not the (huge) size hint."""
    bucket = _create_bucket(ctx)
    role = _create_firehose_role(ctx, bucket)
    firehose = ctx.client("firehose")
    # SizeInMBs at its maximum (128) so the tiny payload below can never cross it;
    # IntervalInSeconds at its minimum (60) so the interval is the only trigger available.
    stream_name = _create_s3_stream(
        ctx, firehose, bucket, role["role_arn"],
        buffering_hints={"SizeInMBs": 128, "IntervalInSeconds": 60},
    )
    _wait_stream_active(ctx, firehose, stream_name)

    marker = ctx.unique_name("interval-marker-")
    firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": f"{marker}\n".encode("utf-8")})

    # Well inside the 60s interval: check absence repeatedly (not sleep-then-check-once), so
    # a target that is merely slower than expected can never be mistaken for one that withheld
    # the record on purpose.
    s3 = ctx.client("s3")
    early_deadline = time.monotonic() + 40.0
    while time.monotonic() < early_deadline:
        early_keys = _list_object_keys(s3, bucket)
        assert early_keys == [], f"record delivered before the buffer interval elapsed: {early_keys}"
        time.sleep(5.0)

    # Poll past the interval for the flush to actually happen.
    lines = _poll_until(
        lambda: _collect_s3_lines(s3, bucket),
        lambda ls: any(marker in line for line in ls),
        timeout_s=150.0,
        interval_s=5.0,
    )
    assert any(marker in line for line in lines), f"marker record never delivered: {lines}"


# ===== helpers =====

def _bucket_arn(name: str) -> str:
    return f"arn:aws:s3:::{name}"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-fh-").lower().replace("_", "-")
    if ctx.region and ctx.region != "us-east-1":
        # us-east-1 rejects create_bucket when LocationConstraint is supplied for its own region.
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    else:
        s3.create_bucket(Bucket=name)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "purpose", "Value": "behavioral-check"}]})

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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
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


def _create_s3_stream(ctx, firehose, bucket, role_arn, buffering_hints, prefix=None) -> str:
    name = ctx.unique_name("sim2real-behav-fh-stream-")
    s3_config = {
        "RoleARN": role_arn,
        "BucketARN": _bucket_arn(bucket),
        "BufferingHints": buffering_hints,
    }
    if prefix:
        s3_config["Prefix"] = prefix

    # A role created moments ago may not yet be assumable by Firehose; retry the
    # role-not-ready rejection on a bounded deadline instead of sleeping upfront and hoping.
    deadline = time.monotonic() + 90.0
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                S3DestinationConfiguration=s3_config,
                Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
            )
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = str(exc).lower()
            role_not_ready = "not authorized" in msg or "unable to assume role" in msg
            if code == "InvalidArgumentException" and role_not_ready and time.monotonic() < deadline:
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


def _list_object_keys(s3, bucket) -> list[str]:
    resp = s3.list_objects_v2(Bucket=bucket)
    return [o["Key"] for o in resp.get("Contents", [])]


def _collect_s3_lines(s3, bucket) -> list[str]:
    keys = _list_object_keys(s3, bucket)
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
