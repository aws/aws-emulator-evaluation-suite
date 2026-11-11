"""e2e-update-destination-stale-version-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-update-destination-stale-version-rejected"
GROUP = "e2e"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDestination with a stale version id fails with ConcurrentModificationException and its
    payload never appears in Describe; an update with the current version id still succeeds."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    firehose = ctx.client("firehose")

    bucket = ctx.unique_name("sim2real-fh-stale-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, s3, bucket))

    role_arn = _create_firehose_role(ctx, iam, bucket)

    stream_name = ctx.unique_name("sim2real-fh-stale-")
    _create_stream_with_retry(
        ctx,
        firehose,
        DeliveryStreamName=stream_name,
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration={
            "BucketARN": f"arn:aws:s3:::{bucket}",
            "RoleARN": role_arn,
            "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
        },
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
    )
    ctx.on_cleanup(lambda: _delete_stream_if_present(ctx, firehose, stream_name))
    _wait_stream_active(ctx, firehose, stream_name)

    desc0 = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
    stale_version = desc0["VersionId"]
    destination_id = desc0["Destinations"][0]["DestinationId"]

    # first legitimate update (with the correct, current version) -- succeeds and bumps the version
    firehose.update_destination(
        DeliveryStreamName=stream_name,
        CurrentDeliveryStreamVersionId=stale_version,
        DestinationId=destination_id,
        ExtendedS3DestinationUpdate={
            "BucketARN": f"arn:aws:s3:::{bucket}",
            "RoleARN": role_arn,
            "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 5},
        },
    )
    desc1 = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
    assert desc1["VersionId"] != stale_version, (
        f"expected VersionId to advance from {stale_version!r}, still {desc1['VersionId']!r}"
    )
    size1 = desc1["Destinations"][0]["ExtendedS3DestinationDescription"]["BufferingHints"]["SizeInMBs"]
    assert size1 == 5, f"expected first update's SizeInMBs=5 to land, got {size1}"

    # second update reuses the now-stale version id from before the first update -> rejected
    code, msg = _error_code(
        lambda: firehose.update_destination(
            DeliveryStreamName=stream_name,
            CurrentDeliveryStreamVersionId=stale_version,
            DestinationId=destination_id,
            ExtendedS3DestinationUpdate={
                "BucketARN": f"arn:aws:s3:::{bucket}",
                "RoleARN": role_arn,
                "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 10},
            },
        )
    )
    assert code == "ConcurrentModificationException", (
        f"expected ConcurrentModificationException for a stale CurrentDeliveryStreamVersionId, got {code}"
    )
    expected_msg = (
        f"Cannot update firehose: {stream_name} since the current version id: {desc1['VersionId']} "
        f"and specified version id: {stale_version} do not match"
    )
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # effect absent: the stale/rejected update's payload (SizeInMBs=10) never landed
    desc2 = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
    assert desc2["VersionId"] == desc1["VersionId"], (
        f"rejected update must not advance VersionId: expected {desc1['VersionId']!r}, got {desc2['VersionId']!r}"
    )
    size2 = desc2["Destinations"][0]["ExtendedS3DestinationDescription"]["BufferingHints"]["SizeInMBs"]
    assert size2 == 5, f"rejected update's SizeInMBs=10 must not land; expected still 5, got {size2}"

    # positive control: a further update using the correct current version still succeeds
    firehose.update_destination(
        DeliveryStreamName=stream_name,
        CurrentDeliveryStreamVersionId=desc2["VersionId"],
        DestinationId=destination_id,
        ExtendedS3DestinationUpdate={
            "BucketARN": f"arn:aws:s3:::{bucket}",
            "RoleARN": role_arn,
            "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 2},
        },
    )
    desc3 = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
    assert desc3["VersionId"] != desc2["VersionId"], (
        f"expected VersionId to advance again from {desc2['VersionId']!r}, still {desc3['VersionId']!r}"
    )
    size3 = desc3["Destinations"][0]["ExtendedS3DestinationDescription"]["BufferingHints"]["SizeInMBs"]
    assert size3 == 2, f"expected the restore update's SizeInMBs=2 to land, got {size3}"


def _error_code(fn):
    """Call fn(), which must fail; return (Error.Code, Error.Message); a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_bucket(ctx, s3, name: str) -> None:
    # us-east-1 is S3's default region: CreateBucketConfiguration is rejected there
    # (MalformedXML) and must be omitted, unlike every other region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "purpose", "Value": "behavioral-check"}]}
    )


def _empty_and_delete_bucket(ctx, s3, bucket: str) -> None:
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_firehose_role(ctx, iam, bucket: str) -> str:
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, iam, role_name))
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
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3access", PolicyDocument=json.dumps(policy))
    return role_arn


def _delete_role(ctx, iam, role_name: str) -> None:
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_stream_with_retry(ctx, firehose, timeout_s: float = 90.0, **kwargs) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            firehose.create_delivery_stream(**kwargs)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidArgumentException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _wait_stream_active(ctx, firehose, name: str, timeout_s: float = 300.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        if status.endswith("FAILED"):
            raise AssertionError(f"stream {name} entered {status}: {desc.get('FailureDescription')}")
        time.sleep(5)
    raise AssertionError(f"stream {name} did not become ACTIVE within {timeout_s}s")


def _delete_stream_if_present(ctx, firehose, name: str) -> None:
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
