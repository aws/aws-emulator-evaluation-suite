"""update-destination-stale-version-id-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "update-destination-stale-version-id-rejected"
GROUP = "server-side"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDestination with a stale CurrentDeliveryStreamVersionId fails with
    ConcurrentModificationException and leaves the destination unmodified; retrying the same update
    with the fresh VersionId succeeds."""
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)
    name = ctx.unique_name("sim2real-behav-frh-")
    _create_s3_stream_with_retry(ctx, name, bucket, role_arn)
    desc = _wait_stream_active(ctx, name)
    destination_id = desc["Destinations"][0]["DestinationId"]
    stale_version_id = desc["VersionId"]

    firehose = ctx.client("firehose")
    # Advance the stream's VersionId once via a legitimate update, so stale_version_id
    # (still held from before) is now provably out of date.
    firehose.update_destination(
        DeliveryStreamName=name,
        CurrentDeliveryStreamVersionId=stale_version_id,
        DestinationId=destination_id,
        S3DestinationUpdate={"Prefix": "bump-1/"},
    )
    desc_bumped = _wait_version_bump(ctx, name, stale_version_id)
    current_version_id = desc_bumped["VersionId"]
    assert current_version_id != stale_version_id, (
        f"VersionId must advance past {stale_version_id!r} after a legitimate update, "
        f"got {current_version_id!r}"
    )

    err = _error(lambda: firehose.update_destination(
        DeliveryStreamName=name,
        CurrentDeliveryStreamVersionId=stale_version_id,  # deliberately stale
        DestinationId=destination_id,
        S3DestinationUpdate={"Prefix": "should-not-apply/"},
    ))
    assert err["Code"] == "ConcurrentModificationException", (
        f"expected ConcurrentModificationException, got {err!r}"
    )
    expected_msg = (
        f"Cannot update firehose: {name} since the current version id: {current_version_id} "
        f"and specified version id: {stale_version_id} do not match"
    )
    assert err.get("Message") == expected_msg, (
        f"expected message {expected_msg!r}, got {err.get('Message')!r}"
    )

    desc_after_reject = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
    assert desc_after_reject["VersionId"] == current_version_id, "rejected stale update must not bump VersionId"
    assert desc_after_reject["Destinations"][0]["S3DestinationDescription"]["Prefix"] == "bump-1/", (
        "rejected stale update must not have applied its Prefix change"
    )

    # Positive control: the same shape of update, using the now-current VersionId, succeeds.
    firehose.update_destination(
        DeliveryStreamName=name,
        CurrentDeliveryStreamVersionId=current_version_id,
        DestinationId=destination_id,
        S3DestinationUpdate={"Prefix": "bump-2/"},
    )
    desc_final = _wait_version_bump(ctx, name, current_version_id)
    final_prefix = desc_final["Destinations"][0]["S3DestinationDescription"]["Prefix"]
    assert final_prefix == "bump-2/", (
        f"positive-control update with the fresh VersionId must apply its Prefix change, "
        f"expected 'bump-2/', got {final_prefix!r}"
    )



def _error(fn):
    """Call fn(); return the botocore Error dict (Code, Message). An unexpected success
    raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, the call succeeded with {result!r}")


def _safe(fn, *missing: str) -> None:
    """Run a teardown call; return quietly only on the given not-found codes, raise the rest."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in missing:
            raise


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-frh-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(lambda: _safe(_cleanup, "NoSuchBucket"))
    return bucket


def _create_firehose_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-frh-role-")
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
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    policy_name = f"{role_name}-policy"
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject",
                "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject",
            ],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name), "NoSuchEntity"))
    return role_arn


def _create_s3_stream_with_retry(
    ctx, name: str, bucket: str, role_arn: str,
    buffering_hints: dict[str, Any] | None = None,
    compression: str | None = None,
    timeout_s: float = 90.0,
) -> None:
    from botocore.exceptions import ClientError

    firehose = ctx.client("firehose")
    s3_config: dict[str, Any] = {"RoleARN": role_arn, "BucketARN": f"arn:aws:s3:::{bucket}"}
    if buffering_hints:
        s3_config["BufferingHints"] = buffering_hints
    if compression:
        s3_config["CompressionFormat"] = compression
    ctx.on_cleanup(lambda: _safe(
        lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True),
        "ResourceNotFoundException",
    ))
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            firehose.create_delivery_stream(DeliveryStreamName=name, S3DestinationConfiguration=s3_config)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = str(exc).lower()
            role_not_ready = "not authorized" in msg or "unable to assume role" in msg
            if code == "InvalidArgumentException" and role_not_ready and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _wait_stream_active(ctx, name: str, timeout_s: float = 120.0) -> dict[str, Any]:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status in ("CREATING_FAILED", "DELETING_FAILED"):
            raise AssertionError(f"delivery stream {name} entered {status}")
        time.sleep(3)
    raise AssertionError(f"delivery stream {name} did not become ACTIVE within {timeout_s}s")


def _wait_version_bump(ctx, name: str, old_version_id: str, timeout_s: float = 60.0) -> dict[str, Any]:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    desc: dict[str, Any] = {}
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        if desc["VersionId"] != old_version_id:
            return desc
        time.sleep(2)
    raise AssertionError(f"VersionId never bumped past {old_version_id} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
