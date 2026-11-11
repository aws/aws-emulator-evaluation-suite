"""tag-value-exceeds-max-length-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable, Iterable, Optional

from behavioral_harness import tags

CHECK = "tag-value-exceeds-max-length-rejected"
GROUP = "overly-permissive"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagDeliveryStream rejects a tag value longer than the documented 256-character
    maximum rather than truncating or accepting it; the tag is never attached. A value
    at the exact 256-character boundary succeeds."""
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
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name, AllowForceDelete=True))
    status = _wait_for_stream_status(ctx, firehose, stream_name, {"ACTIVE", "CREATING_FAILED"})
    assert status == "ACTIVE", f"expected stream to reach ACTIVE, got {status}"

    # Negative: tag value one character over the 256-character maximum.
    too_long_value = "v" * 257
    err = _error(
        lambda: firehose.tag_delivery_stream(
            DeliveryStreamName=stream_name, Tags=[{"Key": "toolong", "Value": too_long_value}]
        )
    )
    # Empirically (real AWS), a tag value exceeding the 256-char maximum fails
    # constraint (length) validation at the API-shape level and is reported as
    # ValidationException, not InvalidArgumentException.
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err!r}"
    expected_msg = (
        "1 validation error detected: Value at 'tags.1.member.value' failed to satisfy "
        "constraint: Member must have length less than or equal to 256"
    )
    assert err.get("Message") == expected_msg, (
        f"expected message {expected_msg!r}, got {err.get('Message')!r}"
    )

    # Effect absent: the rejected tag was never attached.
    tags = firehose.list_tags_for_delivery_stream(DeliveryStreamName=stream_name)["Tags"]
    assert "toolong" not in {t["Key"] for t in tags}, "over-length tag value was persisted"

    # Positive control: a value at the exact 256-character boundary succeeds.
    boundary_value = "v" * 256
    firehose.tag_delivery_stream(DeliveryStreamName=stream_name, Tags=[{"Key": "boundary", "Value": boundary_value}])
    tags_after = firehose.list_tags_for_delivery_stream(DeliveryStreamName=stream_name)["Tags"]
    by_key = {t["Key"]: t["Value"] for t in tags_after}
    assert by_key.get("boundary") == boundary_value, "256-char boundary tag value was not persisted correctly"


def _error(fn: Callable[[], Any]) -> dict:
    """Call fn(); return its botocore Error dict (Code, Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a tag value real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected TagDeliveryStream to reject the over-length value, but it SUCCEEDED and returned {result!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
