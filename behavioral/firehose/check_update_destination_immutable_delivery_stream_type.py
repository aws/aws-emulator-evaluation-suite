"""update-destination-immutable-delivery-stream-type."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-destination-immutable-delivery-stream-type"
GROUP = "server-side"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDestination from an S3 destination to an HTTP endpoint fails with InvalidArgumentException and its exact
    message, leaving the S3 destination and VersionId as they were; a same-family S3 update then applies."""
    firehose = ctx.client("firehose")

    bucket, bucket_arn = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket_arn)

    stream_name = ctx.unique_name("sim2real-fh-immut-")
    _create_delivery_stream_with_role_retry(
        firehose,
        DeliveryStreamName=stream_name,
        DeliveryStreamType="DirectPut",
        S3DestinationConfiguration={
            "RoleARN": role_arn,
            "BucketARN": bucket_arn,
            "Prefix": "before/",
        },
    )
    ctx.on_cleanup(lambda: _delete_stream_and_wait(ctx, stream_name))
    desc = _wait_stream_active(ctx, stream_name)
    destination_id = desc["Destinations"][0]["DestinationId"]
    version_before = desc["VersionId"]

    err = _error(lambda: firehose.update_destination(
        DeliveryStreamName=stream_name,
        CurrentDeliveryStreamVersionId=version_before,
        DestinationId=destination_id,
        HttpEndpointDestinationUpdate={
            "EndpointConfiguration": {"Url": "https://example.invalid/ingest", "Name": "mismatched"},
            "RoleARN": role_arn,
        },
    ))
    assert err["Code"] == "InvalidArgumentException", f"expected InvalidArgumentException, got {err!r}"
    expected_msg = "Changing the destination type to or from HttpEndpoint is not supported at this time."
    assert err.get("Message") == expected_msg, (
        f"expected message {expected_msg!r}, got {err.get('Message')!r}"
    )

    desc_after_reject = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
    assert desc_after_reject["VersionId"] == version_before, "rejected update must not bump VersionId"
    dest_after_reject = desc_after_reject["Destinations"][0]
    assert "S3DestinationDescription" in dest_after_reject, "S3 destination must remain intact"
    assert "HttpEndpointDestinationDescription" not in dest_after_reject, "destination family must not have changed"
    assert dest_after_reject["S3DestinationDescription"]["Prefix"] == "before/", (
        f"S3 prefix must be unchanged by the rejected update, got "
        f"{dest_after_reject['S3DestinationDescription']['Prefix']!r}"
    )

    # Positive control: a same-family update against the same version succeeds.
    firehose.update_destination(
        DeliveryStreamName=stream_name,
        CurrentDeliveryStreamVersionId=version_before,
        DestinationId=destination_id,
        S3DestinationUpdate={"Prefix": "after/"},
    )
    desc_after_accept = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
    assert desc_after_accept["VersionId"] != version_before, "accepted same-family update must bump VersionId"
    accepted_prefix = desc_after_accept["Destinations"][0]["S3DestinationDescription"]["Prefix"]
    assert accepted_prefix == "after/", f"expected accepted update to apply Prefix='after/', got {accepted_prefix!r}"


def _error(fn):
    """Call fn(); return the botocore Error dict (Code, Message). An unexpected success
    raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, the call succeeded with {result!r}")


def _create_delivery_stream_with_role_retry(firehose, timeout_s: float = 90, **kwargs):
    from botocore.exceptions import ClientError
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


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-fh-immut-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    return bucket, f"arn:aws:s3:::{bucket}"


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_firehose_role(ctx, bucket_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:AbortMultipartUpload",
                    "s3:GetBucketLocation",
                    "s3:GetObject",
                    "s3:ListBucket",
                    "s3:ListBucketMultipartUploads",
                    "s3:PutObject",
                ],
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
            }
        ],
    }
    policy_name = "s3-access"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _wait_stream_active(ctx, name, timeout_s=180):
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        last_status = desc["DeliveryStreamStatus"]
        if last_status == "ACTIVE":
            return desc
        if last_status == "CREATING_FAILED":
            raise AssertionError(f"delivery stream {name} entered CREATING_FAILED")
        time.sleep(3)
    raise AssertionError(f"delivery stream {name} not ACTIVE after {timeout_s}s (last={last_status})")


def _delete_stream_and_wait(ctx, name, timeout_s=90):
    firehose = ctx.client("firehose")
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            firehose.describe_delivery_stream(DeliveryStreamName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
