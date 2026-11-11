"""stop-encryption-nonexistent-stream-not-found."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stop-encryption-nonexistent-stream-not-found"
GROUP = "error-semantics"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopDeliveryStreamEncryption on a stream name that does not exist returns
    ResourceNotFoundException, while the same operation on a real, encrypted stream
    (positive control) succeeds end-to-end and drives the status to DISABLED."""
    firehose = ctx.client("firehose")

    nonexistent = ctx.unique_name("sim2real-fh-missing-")
    code, message = _error_code(
        lambda: firehose.stop_delivery_stream_encryption(DeliveryStreamName=nonexistent)
    )
    assert code == "ResourceNotFoundException", (
        f"stop_delivery_stream_encryption on nonexistent stream {nonexistent}: "
        f"expected ResourceNotFoundException, got {code}"
    )
    expected = f"Firehose under accountId {ctx.account} not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: a real stream with encryption ENABLED can be stopped successfully.
    role_arn = _iam_role_for_firehose(ctx)
    _bucket_name, bucket_arn = _s3_bucket(ctx)
    stream_name = ctx.unique_name("sim2real-fh-stopenc-")
    _create_delivery_stream_with_retry(
        firehose,
        DeliveryStreamName=stream_name,
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration=_basic_s3_dest(bucket_arn, role_arn),
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))
    _wait_stream_active(ctx, stream_name)

    firehose.start_delivery_stream_encryption(
        DeliveryStreamName=stream_name,
        DeliveryStreamEncryptionConfigurationInput={"KeyType": "AWS_OWNED_CMK"},
    )
    status = _poll_encryption_status(ctx, stream_name, {"ENABLED"}, timeout_s=90.0)
    assert status == "ENABLED", f"expected encryption status ENABLED after start_delivery_stream_encryption, got {status}"

    firehose.stop_delivery_stream_encryption(DeliveryStreamName=stream_name)
    status2 = _poll_encryption_status(ctx, stream_name, {"DISABLED"}, timeout_s=90.0)
    assert status2 == "DISABLED", f"expected encryption status DISABLED after stop_delivery_stream_encryption, got {status2}"


def _error_code(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected a ClientError, but the call succeeded")


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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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


def _s3_bucket(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-bkt-")
    kwargs: dict[str, Any] = {}
    if ctx.region != "us-east-1":  # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1

        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
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


def _create_delivery_stream_with_retry(firehose, *, timeout_s: float = 90.0, interval_s: float = 5.0, **kwargs) -> dict:
    """IAM role trust can take a while to propagate; retry the create call on the
    IAM-propagation flavor of InvalidArgumentException until it settles."""
    deadline = time.monotonic() + timeout_s
    last_err: Any = None
    while time.monotonic() < deadline:
        try:
            return firehose.create_delivery_stream(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidArgumentException":
                raise
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"create_delivery_stream kept failing with InvalidArgumentException: {last_err}")


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


def _poll_encryption_status(ctx, name: str, target_statuses: set[str], timeout_s: float = 90.0) -> str:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    last = "UNKNOWN"
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        enc = desc.get("DeliveryStreamEncryptionConfiguration") or {}
        last = enc.get("Status", "DISABLED")
        if last in target_statuses:
            return last
        if last.endswith("_FAILED"):
            raise AssertionError(f"encryption entered failed state {last}")
        time.sleep(3)
    raise AssertionError(f"encryption status never reached {target_statuses}, last was {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
