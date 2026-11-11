"""create-trail-bucket-without-policy-fails."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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


def _empty_and_delete_bucket(s3, bucket, *, attempts=6, delay_s=10.0):
    """Empty and delete the bucket, retrying because CloudTrail may still be delivering, and
    RAISE on a genuine deadline miss so a leaked billable bucket is visible rather than silent."""
    last = None
    for attempt in range(attempts):
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket):
                objs = page.get("Contents", [])
                if objs:
                    s3.delete_objects(
                        Bucket=bucket,
                        Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                    )
        except ClientError:
            pass
        try:
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchBucket":
                return
            last = exc
            if attempt < attempts - 1:
                time.sleep(delay_s)
    raise AssertionError(
        f"could not delete bucket {bucket} after {attempts} attempts; a billable S3 bucket has "
        f"been leaked. Last error: {last}"
    )


def _create_bucket_only_tracked(ctx, s3, bucket):
    _create_bucket_only(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]})
    return bucket


CHECK = "create-trail-bucket-without-policy-fails"
GROUP = 'overly-permissive'
SERVICES = ['cloudtrail']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrail against a bucket lacking the CloudTrail delivery policy must be rejected."""
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-ct-trail-")
    bare_bucket = _create_bucket_only_tracked(ctx, s3, ctx.unique_name("sim2real-behav-ct-bkt-").lower())

    code, message = _error(
        lambda: ct.create_trail(Name=name, S3BucketName=bare_bucket)
    )
    assert code == "InsufficientS3BucketPolicyException", (
        f"expected InsufficientS3BucketPolicyException creating a trail against a bucket with "
        f"no CloudTrail delivery policy, got {code!r}"
    )
    assert message == f"Incorrect S3 bucket policy is detected for bucket: {bare_bucket}", message

    account = ctx.client("sts").get_caller_identity()["Account"]
    get_code, get_message = _error(lambda: ct.get_trail(Name=name))
    assert get_code == "TrailNotFoundException", (
        f"GetTrail on the rejected name returned {get_code!r} instead of "
        f"TrailNotFoundException, so a partial trail survived the rejected create"
    )
    assert get_message == f"Unknown trail: {name} for the user: {account}", get_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
