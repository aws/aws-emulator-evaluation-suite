"""list-tags-limit-exceeds-max."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-tags-limit-exceeds-max"
GROUP = "error-semantics"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForDeliveryStream with Limit=50 (the documented maximum) succeeds, while
    Limit=51 (one above the documented maximum) is rejected."""
    role_arn = _iam_role_for_firehose(ctx)
    _bucket_name, bucket_arn = _s3_bucket(ctx)
    firehose = ctx.client("firehose")

    stream_name = ctx.unique_name("sim2real-fh-listtags-")
    _create_stream_with_retry(
        ctx,
        stream_name,
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration=_basic_s3_dest(bucket_arn, role_arn),
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))
    _wait_stream_active(ctx, stream_name)

    firehose.tag_delivery_stream(
        DeliveryStreamName=stream_name,
        Tags=[{"Key": "a", "Value": "1"}, {"Key": "b", "Value": "2"}, {"Key": "c", "Value": "3"}],
    )

    # Positive control: Limit at the documented maximum (50) is accepted.
    resp_ok = firehose.list_tags_for_delivery_stream(DeliveryStreamName=stream_name, Limit=50)
    assert {t["Key"] for t in resp_ok["Tags"]} == {"a", "b", "c"}

    # Negative: Limit=51 (above the documented maximum of 50) is rejected. botocore's client-side
    # param validator only enforces the *min* of a ranged integer shape (see
    # botocore.validate.range_check), never the max, so this request always reaches the service —
    # a ParamValidationError here would mean the request never left the SDK (never a valid
    # rejection signal). The service surfaces the range-trait violation as ValidationException.
    try:
        firehose.list_tags_for_delivery_stream(DeliveryStreamName=stream_name, Limit=51)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ValidationException", f"expected ValidationException, got {code}"
        msg = e.response["Error"].get("Message")
        expected_msg = (
            "1 validation error detected: Value at 'limit' failed to satisfy constraint: "
            "Member must have value less than or equal to 50"
        )
        assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"
    else:
        raise AssertionError("expected ListTagsForDeliveryStream with Limit=51 to be rejected")


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
    if ctx.region != "us-east-1":
        # us-east-1 is S3's own region-pinned default: passing a LocationConstraint for it
        # is rejected, so it is omitted rather than region-derived.
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


_PROPAGATION_HINTS = ("bucket", "assume", "privilege", "not authorized", "does not exist")


def _create_stream_with_retry(ctx, name: str, **kwargs) -> dict:
    """Create a delivery stream, retrying only the propagation flavour of
    InvalidArgumentException (role not yet assumable by firehose.amazonaws.com after
    IAM's create-to-visible lag). A genuine argument error raises immediately."""
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + 120
    while True:
        try:
            return firehose.create_delivery_stream(DeliveryStreamName=name, **kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient = err.get("Code") == "InvalidArgumentException" and any(
                hint in msg for hint in _PROPAGATION_HINTS
            )
            if transient and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


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
