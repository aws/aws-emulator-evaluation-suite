"""create-stream-invalid-kms-key-arn."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-stream-invalid-kms-key-arn"
GROUP = "error-semantics"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeliveryStream synchronously rejects an unusable KMS key ARN in
    DeliveryStreamEncryptionConfigurationInput with InvalidKMSResourceException and leaves no
    delivery stream behind, while an otherwise identical create without a bogus CMK succeeds."""
    role_arn = _iam_role_for_firehose(ctx)
    _bucket_name, bucket_arn = _s3_bucket(ctx)
    firehose = ctx.client("firehose")

    bogus_key_arn = f"arn:aws:kms:{ctx.region}:111122223333:key/00000000-0000-0000-0000-000000000000"
    bad_name = ctx.unique_name("sim2real-fh-badkms-")
    try:
        _create_delivery_stream_with_role_retry(
            firehose,
            DeliveryStreamName=bad_name,
            DeliveryStreamType="DirectPut",
            ExtendedS3DestinationConfiguration=_basic_s3_dest(bucket_arn, role_arn),
            DeliveryStreamEncryptionConfigurationInput={
                "KeyType": "CUSTOMER_MANAGED_CMK",
                "KeyARN": bogus_key_arn,
            },
            Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "InvalidKMSResourceException", (
            f"expected InvalidKMSResourceException for an unusable KMS key ARN, got {code}"
        )
        message = e.response["Error"].get("Message")
        expected = (
            "AccessDenied by KMS while using the CMK. Check the key policy to ensure that the KMS "
            "grant related apis are allowed. Try again after the key policy has the right permissions."
        )
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        raise AssertionError("expected InvalidKMSResourceException for an unusable KMS key ARN")

    # The rejected create must not leave a *usable* delivery stream behind. Real Firehose
    # may still register the name and report a CREATING/CREATING_FAILED delivery stream
    # object (rather than immediately reporting ResourceNotFoundException) even though the
    # CreateDeliveryStream call itself failed synchronously, so accept either outcome but
    # never allow the stream to reach ACTIVE, and clean it up if it exists.
    desc = _wait_terminal_or_gone(ctx, bad_name)
    if desc is not None:
        ctx.on_cleanup(lambda: _delete_stream_and_wait(firehose, bad_name))
        status = desc["DeliveryStreamStatus"]
        assert status != "ACTIVE", f"expected the rejected create to never reach ACTIVE, got {status}"

    # Positive control: the identical destination config without the bogus CMK creates fine.
    good_name = ctx.unique_name("sim2real-fh-goodkms-")
    _create_delivery_stream_with_role_retry(
        firehose,
        DeliveryStreamName=good_name,
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration=_basic_s3_dest(bucket_arn, role_arn),
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
    )
    ctx.on_cleanup(lambda: _delete_stream_and_wait(firehose, good_name))
    desc = _wait_stream_active(ctx, good_name)
    assert desc["DeliveryStreamStatus"] == "ACTIVE", (
        f"expected the positive control to reach ACTIVE, got {desc['DeliveryStreamStatus']}"
    )


#: Bound for a deleted delivery stream to answer not-found, inside the suite's cleanup budget.
_STREAM_DELETE_S = 300.0


def _delete_stream_and_wait(firehose, name: str) -> None:
    """Delete the stream, retrying while it is still CREATING, and poll every 2 s until it is not found."""
    deadline = time.monotonic() + _STREAM_DELETE_S
    deleted = False
    while True:
        status = None
        try:
            if not deleted:
                firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
                deleted = True
            status = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"][
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


def _wait_terminal_or_gone(ctx, name: str, timeout_s: float = 90.0):
    """Poll DescribeDeliveryStream until the stream disappears (ResourceNotFoundException)
    or its status stops being CREATING. Returns the description dict, or None if the
    stream is not found."""
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    last_desc = None
    while time.monotonic() < deadline:
        try:
            last_desc = firehose.describe_delivery_stream(DeliveryStreamName=name)[
                "DeliveryStreamDescription"
            ]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            raise
        if last_desc["DeliveryStreamStatus"] != "CREATING":
            return last_desc
        time.sleep(3)
    return last_desc


def _iam_role_for_firehose(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "firehose.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:*", "kinesis:*", "kms:*"], "Resource": "*"}],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-fh-inline", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-fh-inline"))
    return role_arn


def _create_delivery_stream_with_role_retry(firehose, timeout_s: float = 90.0, **kwargs) -> dict:
    """CreateDeliveryStream synchronously validates that the role is assumable, which can
    transiently fail while IAM's own eventual consistency catches up to a role created moments
    ago; retry on that specific error, bounded, rather than sleeping blind before the first try."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return firehose.create_delivery_stream(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "").lower()
            if code == "InvalidArgumentException" and "role" in msg and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _s3_bucket(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-bkt-")
    kwargs: dict[str, Any] = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real:check", "Value": CHECK}]})
    return name, f"arn:aws:s3:::{name}"


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_object_versions(Bucket=name)
    objs = [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in resp.get("Versions", [])]
    objs += [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in resp.get("DeleteMarkers", [])]
    if objs:
        failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=name)


def _basic_s3_dest(bucket_arn: str, role_arn: str) -> dict:
    return {
        "RoleARN": role_arn,
        "BucketARN": bucket_arn,
        "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
    }


def _wait_stream_active(ctx, name: str, timeout_s: float = 300.0) -> dict:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status == "CREATING_FAILED":
            raise AssertionError(
                f"delivery stream {name} entered CREATING_FAILED: {desc.get('FailureDescription')}"
            )
        time.sleep(5)
    raise AssertionError(f"delivery stream {name} did not become ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
