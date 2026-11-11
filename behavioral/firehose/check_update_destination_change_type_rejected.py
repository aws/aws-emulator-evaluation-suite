"""update-destination-change-type-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable, Iterable, Optional

from behavioral_harness import tags

CHECK = "update-destination-change-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDestination from an S3 destination to an OpenSearch Service one fails with InvalidArgumentException and
    its exact message and leaves the destination and VersionId unchanged; an S3 update then applies."""
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
        S3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": bucket_arn, "Prefix": "orig/"},
        Tags=[{"Key": "purpose", "Value": "sim2real-behavioral-check"}],
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name, AllowForceDelete=True))
    status = _wait_for_stream_status(ctx, firehose, stream_name, {"ACTIVE", "CREATING_FAILED"})
    assert status == "ACTIVE", f"expected stream to reach ACTIVE, got {status}"

    desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
    destination_id = desc["Destinations"][0]["DestinationId"]
    version_id = desc["VersionId"]

    # Switching an S3 destination to OpenSearch is unsupported whether or not the target domain exists
    # ("Switching between Amazon OpenSearch Service and other services is not supported").
    code, message = _error(
        lambda: firehose.update_destination(
            DeliveryStreamName=stream_name,
            CurrentDeliveryStreamVersionId=version_id,
            DestinationId=destination_id,
            AmazonopensearchserviceDestinationUpdate={
                "RoleARN": role_arn,
                "DomainARN": f"arn:aws:es:{ctx.region}:111122223333:domain/does-not-exist",
                "IndexName": "sim2real-index",
            },
        )
    )
    assert code == "InvalidArgumentException", f"expected InvalidArgumentException, got {code!r}: {message!r}"
    expected_msg = (
        "Changing the destination type to/from Elasticsearch/Amazonopensearchservice/"
        "AmazonOpenSearchServerless from/to other destinations is not supported at this time."
    )
    assert message == expected_msg, f"expected message {expected_msg!r}, got {message!r}"

    # Effect absent: destination is still S3, VersionId unchanged.
    desc_after_reject = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
    assert desc_after_reject["VersionId"] == version_id, "VersionId advanced despite the rejected update"
    dest_after_reject = desc_after_reject["Destinations"][0]
    assert "S3DestinationDescription" in dest_after_reject or "ExtendedS3DestinationDescription" in dest_after_reject, (
        f"expected the S3 destination to remain intact, got keys {sorted(dest_after_reject)}"
    )
    assert "AmazonopensearchserviceDestinationDescription" not in dest_after_reject, (
        "the rejected OpenSearch switch must not have been applied"
    )

    # Positive control: a same-type (S3 -> S3) update succeeds and advances VersionId.
    firehose.update_destination(
        DeliveryStreamName=stream_name,
        CurrentDeliveryStreamVersionId=version_id,
        DestinationId=destination_id,
        S3DestinationUpdate={"BucketARN": bucket_arn, "RoleARN": role_arn, "Prefix": "updated/"},
    )
    desc_after_update = _poll_version_advanced(ctx, firehose, stream_name, version_id)
    dest_after_update = desc_after_update["Destinations"][0]
    new_prefix = (
        dest_after_update.get("S3DestinationDescription", {}).get("Prefix")
        or dest_after_update.get("ExtendedS3DestinationDescription", {}).get("Prefix")
    )
    assert new_prefix == "updated/", f"expected updated prefix, got {new_prefix!r}"


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING an update real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_bucket(ctx, s3, name: str) -> None:
    kwargs: dict[str, Any] = {"Bucket": name}
    # us-east-1 is the sole region where CreateBucket rejects an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "purpose", "Value": "sim2real-behavioral-check"}]})

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
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "purpose", "Value": "sim2real-behavioral-check"}],
    )
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


def _poll_version_advanced(
    ctx, firehose, name: str, old_version_id: str, timeout_s: float = 60.0, interval_s: float = 2.0
) -> dict:
    """UpdateDestination is documented as asynchronous ("might not occur immediately"),
    so poll DescribeDeliveryStream until VersionId advances past old_version_id."""
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        if desc["VersionId"] != old_version_id:
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"VersionId for {name} never advanced past {old_version_id} in {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
