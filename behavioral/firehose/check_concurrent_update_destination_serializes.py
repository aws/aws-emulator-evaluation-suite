"""concurrent-update-destination-serializes."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-update-destination-serializes"
GROUP = "concurrency"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateDestination calls racing on the same CurrentDeliveryStreamVersionId
    serialize: exactly one wins and bumps VersionId by exactly one, the other observes
    ConcurrentModificationException, and the final destination config matches the winner."""
    role_arn, bucket_arn = _setup_role_and_bucket(ctx)
    fh = ctx.client("firehose")
    name = ctx.unique_name("sim2real-fh-race-")

    _create_stream_with_retry(ctx, name, role_arn, bucket_arn)
    ctx.on_cleanup(lambda: _safe_delete_stream(ctx, name))
    desc = _wait_for_stream_status(ctx, name, {"ACTIVE"}, timeout_s=240.0)
    dest_id = desc["Destinations"][0]["DestinationId"]
    assert desc["VersionId"] == "1", f"expected a freshly created stream to start at VersionId 1, got {desc['VersionId']}"

    def racer(prefix):
        try:
            fh.update_destination(
                DeliveryStreamName=name,
                CurrentDeliveryStreamVersionId="1",
                DestinationId=dest_id,
                ExtendedS3DestinationUpdate={"Prefix": prefix},
            )
            return ("ok", prefix, None, None)
        except ClientError as e:
            return ("err", prefix, e.response["Error"]["Code"], e.response["Error"].get("Message", ""))

    with ThreadPoolExecutor(max_workers=2) as pool:
        futs = [pool.submit(racer, "racer-a/"), pool.submit(racer, "racer-b/")]
        results = [f.result() for f in futs]

    oks = [r for r in results if r[0] == "ok"]
    errs = [r for r in results if r[0] == "err"]
    assert len(oks) == 1, results
    assert len(errs) == 1, results
    assert errs[0][2] == "ConcurrentModificationException", errs[0]
    # The current version id the loser reads depends on whether the winner has committed, so only it is left open.
    message = errs[0][3]
    assert message.startswith(f"Cannot update firehose: {name} since the current version id: "), message
    assert message.endswith(" and specified version id: 1 do not match"), message

    final = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
    assert final["VersionId"] == "2", f"expected exactly one successful update to bump VersionId from 1 to 2, got {final['VersionId']}"
    winning_prefix = oks[0][1]
    final_prefix = final["Destinations"][0]["ExtendedS3DestinationDescription"]["Prefix"]
    assert final_prefix == winning_prefix, f"expected the persisted config to match the winning racer's prefix {winning_prefix!r}, got {final_prefix!r}"


def _setup_role_and_bucket(ctx):
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-fh-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup_bucket():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup_bucket)
    bucket_arn = f"arn:aws:s3:::{bucket}"

    role_name = ctx.unique_name("sim2real-fh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_name = "sim2real-fh-s3-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject",
                       "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject"],
            "Resource": [bucket_arn, f"{bucket_arn}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))

    def _cleanup_role():
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)
    return role_arn, bucket_arn


def _s3_dest_config(role_arn, bucket_arn, extra=None):
    cfg = {
        "RoleARN": role_arn,
        "BucketARN": bucket_arn,
        "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 5},
    }
    if extra:
        cfg.update(extra)
    return cfg


def _create_stream_with_retry(ctx, name, role_arn, bucket_arn, extra=None, attempts=8, delay_s=15.0):
    """Retries on InvalidArgumentException: a freshly created IAM role/policy is not yet
    visible to Firehose, which rejects CreateDeliveryStream until the permission propagates."""
    fh = ctx.client("firehose")
    cfg = _s3_dest_config(role_arn, bucket_arn, extra)
    last_err = None
    for i in range(attempts):
        try:
            fh.create_delivery_stream(
                DeliveryStreamName=name,
                ExtendedS3DestinationConfiguration=cfg,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidArgumentException" and i < attempts - 1:
                last_err = e
                time.sleep(delay_s)
                continue
            raise
    raise last_err  # pragma: no cover


#: Bound for a deleted delivery stream to answer not-found, inside the suite's cleanup budget.
_STREAM_DELETE_S = 300.0


def _safe_delete_stream(ctx, name):
    """Delete the stream, retrying while it is still CREATING, and poll every 2 s until it is not found."""
    fh = ctx.client("firehose")
    deadline = time.monotonic() + _STREAM_DELETE_S
    deleted = False
    while True:
        status = None
        try:
            if not deleted:
                fh.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
                deleted = True
            status = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"][
                "DeliveryStreamStatus"
            ]
        except ClientError as exc:
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


def _wait_for_stream_status(ctx, name, target_statuses, timeout_s=180.0, interval_s=5.0):
    fh = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        last = desc["DeliveryStreamStatus"]
        if last in target_statuses:
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"stream {name} did not reach {target_statuses} within {timeout_s}s (last={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
