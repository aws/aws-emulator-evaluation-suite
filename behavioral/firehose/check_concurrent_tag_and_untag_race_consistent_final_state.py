"""concurrent-tag-and-untag-race-consistent-final-state."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-tag-and-untag-race-consistent-final-state"
GROUP = "concurrency"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent TagDeliveryStream and UntagDeliveryStream calls on disjoint tag keys
    converge to a single consistent final tag set with no lost updates."""
    bucket = _create_bucket(ctx)
    role = _create_firehose_role(ctx, bucket)
    firehose = ctx.client("firehose")
    stream_name = _create_s3_stream(
        ctx, firehose, bucket, role["role_arn"],
        buffering_hints={"SizeInMBs": 1, "IntervalInSeconds": 60},
    )
    _wait_stream_active(ctx, firehose, stream_name)

    firehose.tag_delivery_stream(
        DeliveryStreamName=stream_name,
        Tags=[{"Key": "keep", "Value": "1"}, {"Key": "remove", "Value": "1"}],
    )

    def _add_tag():
        firehose.tag_delivery_stream(
            DeliveryStreamName=stream_name, Tags=[{"Key": "added", "Value": "new"}]
        )

    def _remove_tag():
        firehose.untag_delivery_stream(DeliveryStreamName=stream_name, TagKeys=["remove"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_add_tag), pool.submit(_remove_tag)]
        for f in futures:
            f.result()

    tags = _poll_until(
        lambda: {t["Key"]: t["Value"] for t in firehose.list_tags_for_delivery_stream(
            DeliveryStreamName=stream_name
        )["Tags"]},
        lambda t: "remove" not in t and "added" in t,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert tags == {"keep": "1", "added": "new"}, f"unexpected converged tag state: {tags}"


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


def _create_s3_stream(ctx, firehose, bucket, role_arn, buffering_hints, prefix=None) -> str:
    name = ctx.unique_name("sim2real-behav-fh-stream-")
    s3_config = {
        "RoleARN": role_arn,
        "BucketARN": _bucket_arn(bucket),
        "BufferingHints": buffering_hints,
    }
    if prefix:
        s3_config["Prefix"] = prefix

    # Firehose rejects a brand-new role until IAM's eventual consistency catches up;
    # retry the create on that specific refusal instead of sleeping unconditionally.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            firehose.create_delivery_stream(DeliveryStreamName=name, S3DestinationConfiguration=s3_config)
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            propagating = err.get("Code") == "InvalidArgumentException" and (
                "assume" in msg or "not authorized" in msg or "does not exist" in msg
            )
            if propagating and time.monotonic() < deadline:
                time.sleep(5)
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


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
