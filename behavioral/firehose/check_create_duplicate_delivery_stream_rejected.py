"""create-duplicate-delivery-stream-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-duplicate-delivery-stream-rejected"
GROUP = "overly-permissive"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-creating an ACTIVE delivery stream name is rejected; the original stream is untouched and fresh names still work."""
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket["arn"])
    name = ctx.unique_name("sim2real-fh-dup-")
    ctx.on_cleanup(lambda: _delete_stream_if_exists(ctx, name))
    _create_delivery_stream(ctx, name, bucket["arn"], role_arn)
    before = _wait_active(ctx, name)

    fh = ctx.client("firehose")

    # Break exactly one thing: re-create with the same, already-ACTIVE name.
    code, message, status = _error(
        lambda: fh.create_delivery_stream(
            DeliveryStreamName=name,
            ExtendedS3DestinationConfiguration={"BucketARN": bucket["arn"], "RoleARN": role_arn},
        )
    )
    assert code == "ResourceInUseException", f"expected ResourceInUseException for a name already ACTIVE, got {code!r}"
    assert status == 400, f"expected HTTP 400 for the duplicate create, got {status!r}"
    expected_message = f"Firehose {name} under accountId {ctx.account} already exists"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # Effect absent: the original stream is unchanged, still exactly one stream by this name.
    desc = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
    assert desc["DeliveryStreamStatus"] == "ACTIVE", f"expected the untouched original to stay ACTIVE, got {desc['DeliveryStreamStatus']!r}"
    assert desc["DeliveryStreamName"] == name, f"expected describe to still return {name!r}, got {desc['DeliveryStreamName']!r}"
    # The refused duplicate omitted BufferingHints; the original's destination config must survive.
    hints = desc["Destinations"][0]["ExtendedS3DestinationDescription"]["BufferingHints"]
    assert hints == {"IntervalInSeconds": 60, "SizeInMBs": 1}, (
        f"the refused duplicate changed the original's BufferingHints: {hints!r}"
    )
    assert desc["VersionId"] == before["VersionId"], (
        f"the refused duplicate bumped VersionId: {before['VersionId']!r} -> {desc['VersionId']!r}"
    )

    # Positive control: creation still works normally for a name that is not in use.
    other_name = ctx.unique_name("sim2real-fh-dup-ok-")
    ctx.on_cleanup(lambda: _delete_stream_if_exists(ctx, other_name))
    _create_delivery_stream(ctx, other_name, bucket["arn"], role_arn)
    _wait_active(ctx, other_name)
    _delete_stream_and_wait(ctx, other_name)

    # Restore: freeing the name lifts the conflict, so the identical call now succeeds.
    _delete_stream_and_wait(ctx, name)
    _create_delivery_stream(ctx, name, bucket["arn"], role_arn)
    restored = _wait_active(ctx, name)
    assert restored["DeliveryStreamName"] == name, f"expected the restored stream to be named {name!r}, got {restored['DeliveryStreamName']!r}"

    _delete_stream_and_wait(ctx, name)


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is CreateBucket's implicit default region and rejects a LocationConstraint.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        _empty_bucket(ctx, name)
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


def _empty_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    while True:
        resp = s3.list_objects_v2(Bucket=bucket_name)
        objs = resp.get("Contents", [])
        if not objs:
            return
        s3.delete_objects(Bucket=bucket_name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        if not resp.get("IsTruncated"):
            return


def _create_firehose_role(ctx, bucket_arn: str) -> str:
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
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-write", PolicyDocument=json.dumps(policy))

    def _cleanup():
        iam.delete_role_policy(RoleName=role_name, PolicyName="s3-write")
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_delivery_stream(ctx, name: str, bucket_arn: str, role_arn: str, buffering_seconds: int = 60) -> str:
    fh = ctx.client("firehose")
    config = {
        "BucketARN": bucket_arn,
        "RoleARN": role_arn,
        "BufferingHints": {"IntervalInSeconds": buffering_seconds, "SizeInMBs": 1},
    }
    deadline = time.monotonic() + 90
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = fh.create_delivery_stream(DeliveryStreamName=name, ExtendedS3DestinationConfiguration=config)
            return resp["DeliveryStreamARN"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidArgumentException":
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err


def _delete_stream_if_exists(ctx, name: str) -> None:
    fh = ctx.client("firehose")
    try:
        fh.delete_delivery_stream(DeliveryStreamName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_active(ctx, name: str, timeout_s: float = 150.0):
    fh = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status.endswith("FAILED"):
            raise AssertionError(f"delivery stream entered {status}")
        time.sleep(3)
    raise AssertionError("delivery stream never became ACTIVE")


def _delete_stream_and_wait(ctx, name: str, timeout_s: float = 150.0) -> None:
    fh = ctx.client("firehose")
    fh.delete_delivery_stream(DeliveryStreamName=name)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            fh.describe_delivery_stream(DeliveryStreamName=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(3)
    raise AssertionError("delivery stream was not removed in time")


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message, HTTP status) of its ClientError. An
    unexpected success raises, so a target accepting what AWS refuses cannot read as a mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return (e.response["Error"]["Code"], e.response["Error"].get("Message"),
                e.response.get("ResponseMetadata", {}).get("HTTPStatusCode"))
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
