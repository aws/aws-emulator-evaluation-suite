"""tag-delivery-stream-disallowed-key-character-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-delivery-stream-disallowed-key-character-rejected"
GROUP = "overly-permissive"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagDeliveryStream with a key containing a character outside the allowed tag-key
    charset (Unicode letters/digits/whitespace and _ . / = + - @) is rejected and the
    tag is never persisted."""
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)
    stream_name = _create_s3_delivery_stream(ctx, role_arn, bucket, prefix="reserved-tag-test/")

    firehose = ctx.client("firehose")

    err = _error(
        lambda: firehose.tag_delivery_stream(
            DeliveryStreamName=stream_name,
            Tags=[{"Key": "invalid!key#name", "Value": "should-not-persist"}],
        )
    )
    # AWS enforces the Tag.Key Pattern trait (Unicode letters/digits/whitespace and
    # _ . : / = + - @ % only) server-side via the modeled input-validation framework,
    # which surfaces as ValidationException (distinct from the firehose-specific
    # business-logic InvalidArgumentException).
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err!r}"
    expected_msg = (
        "1 validation error detected: Value at 'tags.1.member.key' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: "
        r"^(?!aws:)[\p{L}\p{Z}\p{N}_.:\/=+\-@%]*$"
    )
    assert err.get("Message") == expected_msg, (
        f"expected message {expected_msg!r}, got {err.get('Message')!r}"
    )

    tags_after_reject = firehose.list_tags_for_delivery_stream(DeliveryStreamName=stream_name)[
        "Tags"
    ]
    assert not any(t["Key"] == "invalid!key#name" for t in tags_after_reject), (
        f"rejected tag key must not be persisted, got {tags_after_reject!r}"
    )

    # Positive control: a non-reserved key on the very same stream succeeds and is visible.
    firehose.tag_delivery_stream(
        DeliveryStreamName=stream_name,
        Tags=[{"Key": "valid-tag-key", "Value": "valid-tag-value"}],
    )
    tags_after_accept = firehose.list_tags_for_delivery_stream(DeliveryStreamName=stream_name)[
        "Tags"
    ]
    matches = [t for t in tags_after_accept if t["Key"] == "valid-tag-key"]
    assert len(matches) == 1, f"expected exactly one valid-tag-key tag, got {matches!r}"
    assert matches[0]["Value"] == "valid-tag-value", (
        f"expected value 'valid-tag-value', got {matches[0]['Value']!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-fh-s3-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_firehose_role(ctx, bucket: str) -> str:
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
    policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_s3_delivery_stream(ctx, role_arn: str, bucket: str, prefix: str, buffering_hints=None) -> str:
    firehose = ctx.client("firehose")
    name = ctx.unique_name("sim2real-fh-stream-")
    hints = buffering_hints or {"SizeInMBs": 1, "IntervalInSeconds": 60}
    config = {
        "RoleARN": role_arn,
        "BucketARN": f"arn:aws:s3:::{bucket}",
        "Prefix": prefix,
        "BufferingHints": hints,
        "CompressionFormat": "UNCOMPRESSED",
    }
    deadline = time.monotonic() + 90.0
    last_err: Exception | None = None
    created = False
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=config,
            )
            created = True
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidArgumentException":
                last_err = e
                time.sleep(5)
                continue
            raise
    if not created:
        raise AssertionError(f"delivery stream never created (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=name))
    _wait_for_stream_active(ctx, name)
    return name


def _wait_for_stream_active(ctx, name: str, timeout_s: float = 120.0) -> None:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError(f"delivery stream {name} never became ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
