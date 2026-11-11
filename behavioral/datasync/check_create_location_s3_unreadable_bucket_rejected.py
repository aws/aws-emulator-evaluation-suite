"""create-location-s3-unreadable-bucket-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-location-s3-unreadable-bucket-rejected"
GROUP = "access-validation"
SERVICES = ["datasync"]


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "plane:control")
def run(ctx) -> None:
    """CreateLocationS3 with a role whose policy names only one of two identical buckets creates the readable
    bucket's location and fails for the other with InvalidRequestException and the exact access-test message,
    leaving no location for it: the service tests access as the role."""
    s3 = ctx.client("s3")
    ds = ctx.client("datasync")

    readable = _create_bucket(ctx, "sim2real-ds-readable-")
    unreadable = _create_bucket(ctx, "sim2real-ds-unreadable-")
    for bucket in (readable, unreadable):
        s3.put_object(Bucket=bucket, Key="alpha.txt", Body=b"A" * 100)

    # The role's policy names the readable bucket ONLY.
    _role_name, role_arn = _create_datasync_role(ctx, [readable])

    # Positive control first, which also establishes that the role has propagated and is
    # assumable — so the refusal below cannot be an IAM-propagation artefact.
    readable_loc = _create_s3_location(ctx, readable, role_arn)
    described = ds.describe_location_s3(LocationArn=readable_loc)
    assert described["LocationUri"] == f"s3://{readable}/", (
        f"readable location URI is {described['LocationUri']!r}, expected 's3://{readable}/'"
    )
    assert described["S3Config"]["BucketAccessRoleArn"] == role_arn, (
        f"readable location carries role {described['S3Config']['BucketAccessRoleArn']!r}, expected {role_arn!r}"
    )

    # The refusal: same role, same request shape, a bucket its policy does not name.
    code, message = _error(
        lambda: ds.create_location_s3(
            S3BucketArn=f"arn:aws:s3:::{unreadable}",
            Subdirectory="/",
            S3Config={"BucketAccessRoleArn": role_arn},
        )
    )
    assert code == "InvalidRequestException", (
        f"CreateLocationS3 for an unreadable bucket failed with {code!r}, expected 'InvalidRequestException'"
    )
    expected_message = (
        f"DataSync location access test failed: could not perform s3:ListObjectsV2 on bucket {unreadable}. "
        "Access denied. Ensure bucket access role has s3:ListBucket permission."
    )
    assert message == expected_message, (
        f"CreateLocationS3 for an unreadable bucket said {message!r}, expected {expected_message!r}"
    )

    # The effect is absent: no location for the unreadable bucket exists, while the readable
    # one does. The listing is filtered to the two buckets this check created, so a sibling
    # run in the same account cannot change the answer.
    mine = {}
    for location in _list_locations(ctx):
        uri = location["LocationUri"]
        if uri in (f"s3://{readable}/", f"s3://{unreadable}/"):
            mine[uri] = location["LocationArn"]
    assert mine == {f"s3://{readable}/": readable_loc}, (
        f"ListLocations reports {json.dumps(mine)} for this check's buckets, expected only the readable one"
    )


def _error(fn) -> tuple:
    """Return the (code, message) of the AWS error ``fn`` raises; raise if the call succeeds."""
    try:
        fn()
    except Exception as exc:
        error = getattr(exc, "response", {}).get("Error", {})
        code = error.get("Code")
        if code is None:
            raise AssertionError(f"exception carried no AWS error code: {exc!r}") from exc
        return code, error.get("Message")
    raise AssertionError("the call succeeded; real AWS rejects it, so there is no error code to read")


def _create_bucket(ctx, prefix: str) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    # us-east-1 is the one region S3 rejects an explicit LocationConstraint for.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda b=bucket: _empty_and_delete_bucket(ctx, b))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_datasync_role(ctx, buckets: list) -> tuple:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ds-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "datasync.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": role_name}],
    )
    ctx.on_cleanup(lambda rn=role_name: _delete_role(ctx, rn))
    resources = []
    for bucket in buckets:
        resources += [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetBucketLocation",
                    "s3:ListBucket",
                    "s3:ListBucketMultipartUploads",
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:AbortMultipartUpload",
                    "s3:DeleteObject",
                    "s3:GetObjectTagging",
                    "s3:PutObjectTagging",
                ],
                "Resource": resources,
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="datasync-s3", PolicyDocument=json.dumps(policy))
    return role_name, role["Role"]["Arn"]


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_s3_location(ctx, bucket: str, role_arn: str) -> str:
    """CreateLocationS3 runs an access test as the role, so it fails until IAM has propagated.

    No API reports a role as effective, so the bounded retry at first use IS the wait.
    """
    ds = ctx.client("datasync")
    deadline = time.monotonic() + 180.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = ds.create_location_s3(
                S3BucketArn=f"arn:aws:s3:::{bucket}",
                Subdirectory="/",
                S3Config={"BucketAccessRoleArn": role_arn},
                Tags=[{"Key": "sim2real", "Value": bucket}],
            )["LocationArn"]
            ctx.on_cleanup(lambda a=arn: ds.delete_location(LocationArn=a))
            return arn
        except Exception as exc:
            last = exc
            time.sleep(5)
    raise AssertionError(f"CreateLocationS3 never succeeded for {bucket!r} within 180s: {last!r}")


def _list_locations(ctx) -> list:
    ds = ctx.client("datasync")
    out = []
    for page in ds.get_paginator("list_locations").paginate():
        out.extend(page.get("Locations", []))
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
