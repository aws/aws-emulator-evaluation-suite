"""create-trail-invalid-name-fails."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn() and return the (Error.Code, Error.Message) of the ClientError it raises. An
    unexpected SUCCESS raises, so a target that accepts a call real AWS refuses fails loudly
    instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_bucket_only(s3, bucket, region):
    """Create a plain S3 bucket (no CloudTrail policy)."""
    kwargs = {"Bucket": bucket}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise


def _create_trail_bucket(s3, bucket, region, account_id):
    """Create an S3 bucket with the policy CloudTrail needs to deliver logs."""
    _create_bucket_only(s3, bucket, region)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": [
                    f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                    f"arn:aws:s3:::{bucket}/*/AWSLogs/{account_id}/*",
                ],
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def _empty_and_delete_bucket(s3, bucket):
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket,
                    Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_trail_bucket_tracked(ctx, s3, bucket):
    account = ctx.client("sts").get_caller_identity()["Account"]
    _create_trail_bucket(s3, bucket, ctx.region, account)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    return bucket


def _delete_trail(ct, name):
    """Best-effort teardown: stop logging (if on) then delete the trail."""
    try:
        ct.stop_logging(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise
    try:
        ct.delete_trail(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise


CHECK = "create-trail-invalid-name-fails"
GROUP = 'overly-permissive'
SERVICES = ['cloudtrail']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrail enforces the documented trail-name grammar rather than accepting anything."""
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    bucket = _create_trail_bucket_tracked(ctx, s3, ctx.unique_name("sim2real-behav-ct-bkt-").lower())

    # Positive control: this bucket and this account can create a trail with a valid name, so
    # the rejections below are the grammar, not a global inability to create anything.
    control_name = ctx.unique_name("sim2real-behav-ct-trail-")
    ct.create_trail(Name=control_name, S3BucketName=bucket)
    ctx.on_cleanup(lambda: _delete_trail(ct, control_name))
    control_read_name = ct.get_trail(Name=control_name)["Trail"]["Name"]
    assert control_read_name == control_name, f"expected {control_name!r}, got {control_read_name!r}"

    # Illegal character, too short, and adjacent separators are all invalid.
    bad_names = {
        "bad name!": "Trail name must end with a letter or number.",
        "ab": "Trail name too short. Minimum allowed length: 3 characters. Specified name length: 2 characters.",
        "my--namespace": "Trail name or ARN cannot have adjacent periods (.), hyphens (-), or underscores (_).",
    }
    for bad_name, want_msg in bad_names.items():
        code, msg = _error(
            lambda n=bad_name: ct.create_trail(Name=n, S3BucketName=bucket)
        )
        assert code == "InvalidTrailNameException", f"expected InvalidTrailNameException for {bad_name!r}, got {code}"
        assert msg == want_msg, f"{bad_name!r}: {msg!r}"

    # None of the rejected names produced a trail — an independent read at the destination.
    existing_names = {t["Name"] for t in ct.list_trails()["Trails"]}
    for bad_name in bad_names:
        assert bad_name not in existing_names, f"{bad_name!r} unexpectedly present in ListTrails after rejection"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
