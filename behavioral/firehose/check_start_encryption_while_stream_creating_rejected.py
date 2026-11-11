"""start-encryption-while-stream-creating-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable, Iterable, Optional

from behavioral_harness import tags

CHECK = "start-encryption-while-stream-creating-rejected"
GROUP = "overly-permissive"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartDeliveryStreamEncryption is rejected with a wrong-state error while the
    stream is still CREATING (encryption never gets enabled by that call), but the
    identical call succeeds once the stream reaches ACTIVE."""
    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")
    iam = ctx.client("iam")

    bucket_name = ctx.unique_name("sim2real-behav-fhbucket-")
    _create_bucket(ctx, s3, bucket_name)
    bucket_arn = f"arn:aws:s3:::{bucket_name}"
    role_arn = _create_role(ctx, iam, "sim2real-behav-fhrole-", "firehose.amazonaws.com", bucket_arn)

    stream_name = ctx.unique_name("sim2real-behav-fhstream-")
    _create_delivery_stream_with_retry(
        ctx,
        firehose,
        DeliveryStreamName=stream_name,
        S3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": bucket_arn},
    )
    ctx.on_cleanup(lambda: _delete_stream_and_wait(firehose, stream_name))

    # The call is issued right after the create returns: a new stream stays CREATING for
    # tens of seconds, and the read just before the call must see CREATING.
    status = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)[
        "DeliveryStreamDescription"
    ]["DeliveryStreamStatus"]
    assert status == "CREATING", (
        "stream left CREATING before StartDeliveryStreamEncryption could be attempted "
        f"against it; cannot exercise the wrong-state rejection (got {status})"
    )
    code, message = _expect_error(
        lambda: firehose.start_delivery_stream_encryption(
            DeliveryStreamName=stream_name,
            DeliveryStreamEncryptionConfigurationInput={"KeyType": "AWS_OWNED_CMK"},
        )
    )
    assert code == "ResourceInUseException", f"expected ResourceInUseException, got {code}: {message!r}"
    expected = f"Cannot enable encryption on firehose: {stream_name} when it is in CREATING status"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: encryption was not enabled by the rejected call, and the stream
    # still went on to reach ACTIVE normally.
    active_status = _wait_for_stream_status(ctx, firehose, stream_name, {"ACTIVE", "CREATING_FAILED"})
    assert active_status == "ACTIVE", f"expected stream to reach ACTIVE, got {active_status}"
    desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
    enc_status = desc.get("DeliveryStreamEncryptionConfiguration", {}).get("Status", "DISABLED")
    assert enc_status == "DISABLED", f"expected encryption still DISABLED, got {enc_status}"

    # Positive control: the identical call succeeds now that the stream is ACTIVE.
    firehose.start_delivery_stream_encryption(
        DeliveryStreamName=stream_name,
        DeliveryStreamEncryptionConfigurationInput={"KeyType": "AWS_OWNED_CMK"},
    )
    final_enc_status = _poll_encryption_status(ctx, firehose, stream_name, {"ENABLED", "ENABLING_FAILED"})
    assert final_enc_status == "ENABLED", f"expected encryption ENABLED, got {final_enc_status}"


def _expect_error(fn: Callable[[], Any]) -> tuple[str, Optional[str]]:
    """Call fn(), which must fail; return (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_bucket(ctx, s3, name: str) -> None:
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup() -> None:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)


def _create_role(ctx, iam, prefix: str, trust_service: str, bucket_arn: str) -> str:
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    role_name = ctx.unique_name(prefix)
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = resp["Role"]["Arn"]
    policy_name = f"{role_name}-policy"
    access_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:PutObjectAcl", "s3:GetBucketLocation", "s3:ListBucket"],
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(access_policy))

    def _cleanup() -> None:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_delivery_stream_with_retry(
    ctx, firehose, *, timeout_s: float = 90.0, interval_s: float = 5.0, **kwargs
) -> dict:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err: Optional[Exception] = None
    while time.monotonic() < deadline:
        try:
            return firehose.create_delivery_stream(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidArgumentException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"create_delivery_stream kept failing with InvalidArgumentException: {last_err}")


def _delete_stream_and_wait(firehose, name: str, timeout_s: float = 420.0, interval_s: float = 5.0) -> None:
    """Poll to a deletable state, delete, then poll to actual disappearance.
    DeleteDeliveryStream is refused with ResourceInUseException while the stream is
    still CREATING (the state this check deliberately tries to catch, and the state
    it can still be in if the wait for ACTIVE times out) and returns while the stream
    is DELETING -- a fire-and-forget delete therefore silently leaks the stream."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        status = desc["DeliveryStreamStatus"]
        if status != "DELETING":
            try:
                firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
            except ClientError as err:
                code = err.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code != "ResourceInUseException":
                    raise
        time.sleep(interval_s)
    raise AssertionError(f"LEAK: delivery stream {name} still {status} after {timeout_s}s")


def _wait_for_stream_status(
    ctx, firehose, name: str, terminal_statuses: Iterable[str], timeout_s: float = 120.0, interval_s: float = 3.0
) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status in terminal_statuses:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stream {name} did not reach a terminal status in {timeout_s}s, last={status}")


def _poll_status(
    ctx, firehose, name: str, stop_statuses: Iterable[str], timeout_s: float, interval_s: float
) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status in stop_statuses:
            return status
        time.sleep(interval_s)
    return status


def _poll_encryption_status(
    ctx, firehose, name: str, terminal_statuses: Iterable[str], timeout_s: float = 60.0, interval_s: float = 2.0
) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc.get("DeliveryStreamEncryptionConfiguration", {}).get("Status")
        if status in terminal_statuses:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"encryption on {name} did not reach a terminal status in {timeout_s}s, last={status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
