"""tag-delivery-stream-invalid-argument-too-many-tags."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-delivery-stream-invalid-argument-too-many-tags"
GROUP = "error-semantics"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A single TagDeliveryStream call with more tags than the documented 50-item maximum
    is rejected and applies none of the offending tags, while tagging within the limit
    (positive control) succeeds and is reflected by ListTagsForDeliveryStream."""
    role_arn = _iam_role_for_firehose(ctx)
    _bucket_name, bucket_arn = _s3_bucket(ctx)
    firehose = ctx.client("firehose")

    stream_name = ctx.unique_name("sim2real-fh-tags-")
    _create_delivery_stream_with_role_retry(ctx, firehose, stream_name, role_arn, bucket_arn)
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))
    _wait_stream_active(ctx, stream_name)

    # Positive control: tagging with a small, valid set succeeds.
    firehose.tag_delivery_stream(
        DeliveryStreamName=stream_name,
        Tags=[{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "sim2real"}],
    )
    tags_resp = firehose.list_tags_for_delivery_stream(DeliveryStreamName=stream_name)
    got = {t["Key"]: t["Value"] for t in tags_resp["Tags"]}
    assert got == {"env": "test", "owner": "sim2real"}, f"expected the two-tag set, got {got}"

    # Negative: a single call with 51 tags (above the documented 50-item maximum) is
    # rejected. botocore's ParamValidator only enforces a list shape's declared "min", never
    # its "max" (see botocore.validate.BaseParamValidator.VALIDATED_METADATA_ATTRS), so this
    # request is never rejected client-side — it always reaches the service, and only the
    # service's own enforcement can produce the rejection.
    too_many = [{"Key": f"bulk-{i}", "Value": "v"} for i in range(51)]
    try:
        firehose.tag_delivery_stream(DeliveryStreamName=stream_name, Tags=too_many)
    except ClientError as e:
        err = e.response["Error"]
        assert err["Code"] == "ValidationException", (
            f"expected ValidationException for 51 tags, got {err!r}"
        )
        expected_msg = (
            "1 validation error detected: Value at 'tags' failed to satisfy constraint: "
            "Member must have length less than or equal to 50"
        )
        assert err.get("Message") == expected_msg, (
            f"expected message {expected_msg!r}, got {err.get('Message')!r}"
        )
    else:
        raise AssertionError("expected the 51-tag TagDeliveryStream request to be rejected")

    # The rejected call must not have mutated the stream's tag set.
    tags_after = firehose.list_tags_for_delivery_stream(DeliveryStreamName=stream_name)
    got_after = {t["Key"]: t["Value"] for t in tags_after["Tags"]}
    assert got_after == {"env": "test", "owner": "sim2real"}, (
        f"51-tag rejection must not mutate the tag set, got {got_after}"
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


def _create_delivery_stream_with_role_retry(
    ctx, firehose, stream_name: str, role_arn: str, bucket_arn: str, timeout_s: float = 60.0
) -> None:
    """CreateDeliveryStream validates that Firehose can assume role_arn; a role created
    moments ago may not have propagated through IAM yet, so retry on that specific
    rejection (never on any other error) until it clears or the deadline passes."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=stream_name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=_basic_s3_dest(bucket_arn, role_arn),
            )
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            detail = str(e).lower()
            is_role_propagation = code == "InvalidArgumentException" and (
                "not authorized" in detail or "unable to assume role" in detail or "assume role" in detail
            )
            if is_role_propagation and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _s3_bucket(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-bkt-")
    kwargs: dict[str, Any] = {}
    if ctx.region != "us-east-1":
        # us-east-1 is S3's own permanent special case: CreateBucket rejects an explicit
        # LocationConstraint for that region, so it must be omitted rather than pinned.
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
