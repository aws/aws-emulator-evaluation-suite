"""start-encryption-nonexistent-stream-not-found."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-encryption-nonexistent-stream-not-found"
GROUP = 'error-semantics'
SERVICES = ['firehose']

def _err(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartDeliveryStreamEncryption on an unknown stream fails with ResourceNotFoundException and its exact message,
    while the same call on a real unencrypted stream drives encryption to ENABLED."""
    firehose = ctx.client("firehose")

    name = ctx.unique_name("sim2real-behav-fh-enc-absent-")
    code, message = _err(
        lambda: firehose.start_delivery_stream_encryption(
            DeliveryStreamName=name,
            DeliveryStreamEncryptionConfigurationInput={"KeyType": "AWS_OWNED_CMK"},
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"Firehose under accountId {ctx.account} not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the identical call on a real, ACTIVE, unencrypted stream succeeds.
    role_arn = _iam_role_for_firehose(ctx)
    bucket_arn = _s3_bucket(ctx)
    stream_name = ctx.unique_name("sim2real-behav-fh-enc-real-")
    _create_delivery_stream_with_role_retry(
        firehose,
        DeliveryStreamName=stream_name,
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": bucket_arn},
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name, AllowForceDelete=True))
    _wait_stream_active(ctx, stream_name)

    firehose.start_delivery_stream_encryption(
        DeliveryStreamName=stream_name,
        DeliveryStreamEncryptionConfigurationInput={"KeyType": "AWS_OWNED_CMK"},
    )
    status = _poll_encryption_status(ctx, stream_name, {"ENABLED", "ENABLING_FAILED"})
    assert status == "ENABLED", f"expected encryption status ENABLED, got {status}"


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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:*", "kms:*"], "Resource": "*"}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-fh-inline", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-fh-inline"))
    return role_arn


def _create_delivery_stream_with_role_retry(firehose, timeout_s: float = 90.0, **kwargs):
    """CreateDeliveryStream, retrying while the freshly created role's trust/
    inline-policy grant propagates through IAM."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return firehose.create_delivery_stream(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "").lower()
            if code == "InvalidArgumentException" and "assume" in msg:
                last_err = exc
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"could not create delivery stream after role propagation wait: {last_err}")


def _s3_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-bkt-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {}
    if ctx.region != "us-east-1":  # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return f"arn:aws:s3:::{name}"


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


def _wait_stream_active(ctx, name: str, timeout_s: float = 300.0) -> dict:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status == "CREATING_FAILED":
            raise AssertionError(f"delivery stream {name} entered CREATING_FAILED: {desc.get('FailureDescription')}")
        time.sleep(5)
    raise AssertionError(f"delivery stream {name} did not become ACTIVE within {timeout_s}s")


def _poll_encryption_status(ctx, name: str, terminal_statuses: set[str], timeout_s: float = 120.0) -> str:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    last = "UNKNOWN"
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        enc = desc.get("DeliveryStreamEncryptionConfiguration") or {}
        last = enc.get("Status", "DISABLED")
        if last in terminal_statuses:
            return last
        time.sleep(3)
    raise AssertionError(f"encryption status on {name} never reached {terminal_statuses}, last was {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
