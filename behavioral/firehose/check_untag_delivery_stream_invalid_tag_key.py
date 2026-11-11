"""untag-delivery-stream-invalid-tag-key."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "untag-delivery-stream-invalid-tag-key"
GROUP = "error-semantics"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagDeliveryStream refuses a reserved/malformed tag key ('aws:...' prefix) with
    ValidationException and leaves the stream's remaining tags untouched, while removing
    a real tag key (positive control) succeeds."""
    role_arn = _iam_role_for_firehose(ctx)
    _bucket_name, bucket_arn = _s3_bucket(ctx)
    firehose = ctx.client("firehose")

    stream_name = ctx.unique_name("sim2real-fh-untag-")
    _create_delivery_stream_with_retry(
        firehose,
        DeliveryStreamName=stream_name,
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration=_basic_s3_dest(bucket_arn, role_arn),
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))
    _wait_stream_active(ctx, stream_name)

    firehose.tag_delivery_stream(
        DeliveryStreamName=stream_name,
        Tags=[{"Key": "keep", "Value": "1"}, {"Key": "remove", "Value": "1"}],
    )

    # Positive control: removing a real tag key succeeds.
    firehose.untag_delivery_stream(DeliveryStreamName=stream_name, TagKeys=["remove"])
    tags_after_positive = firehose.list_tags_for_delivery_stream(DeliveryStreamName=stream_name)
    positive_tags = {t["Key"]: t["Value"] for t in tags_after_positive["Tags"]}
    assert positive_tags == {"keep": "1"}, f"expected only {{'keep': '1'}} after removing 'remove', got {positive_tags}"

    # Negative: a tag key with the reserved 'aws:' prefix is refused, and the untouched
    # "keep" tag must remain in place. This pattern-trait violation on the TagKey member
    # surfaces as ValidationException (the generic framework constraint-violation error) on
    # real AWS, not the business-logic InvalidArgumentException.
    try:
        firehose.untag_delivery_stream(DeliveryStreamName=stream_name, TagKeys=["aws:reserved-key"])
    except ClientError as e:
        err = e.response["Error"]
        assert err["Code"] == "ValidationException", (
            f"expected ValidationException for a reserved 'aws:' tag key, got {err!r}"
        )
        expected_msg = (
            "1 validation error detected: Value at 'tagKeys' failed to satisfy constraint: "
            "Member must satisfy constraint: [Member must have length less than or equal to "
            "128, Member must have length greater than or equal to 1, Member must satisfy "
            r"regular expression pattern: ^(?!aws:)[\p{L}\p{Z}\p{N}_.:\/=+\-@%]*$]"
        )
        assert err.get("Message") == expected_msg, (
            f"expected message {expected_msg!r}, got {err.get('Message')!r}"
        )
    else:
        raise AssertionError("expected rejection of a reserved 'aws:' tag key")

    tags_after_negative = firehose.list_tags_for_delivery_stream(DeliveryStreamName=stream_name)
    negative_tags = {t["Key"]: t["Value"] for t in tags_after_negative["Tags"]}
    assert negative_tags == {"keep": "1"}, (
        f"expected the refused untag to leave tags at {{'keep': '1'}}, got {negative_tags}"
    )


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


def _create_delivery_stream_with_retry(firehose, timeout_s: float = 60.0, **kwargs) -> dict:
    """Retries CreateDeliveryStream while the IAM role is still propagating (Firehose
    rejects a brand-new role's trust policy until it becomes visible)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return firehose.create_delivery_stream(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = (exc.response.get("Error", {}).get("Message") or "").lower()
            propagating = code == "InvalidArgumentException" and (
                "assume" in msg or "not authorized" in msg or "does not exist" in msg
            )
            if propagating and time.monotonic() < deadline:
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
