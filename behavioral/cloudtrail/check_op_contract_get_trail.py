"""op-contract-get-trail."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-get-trail"
GROUP = "error-semantics"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTrail returns the exact configuration of a trail; a nonexistent trail is rejected."""
    ct = ctx.client("cloudtrail")
    bucket, _account_id = _create_trail_bucket(ctx)
    name = ctx.unique_name("sim2real-ct-trail-")
    _create_trail_retrying(
        ct,
        Name=name,
        S3BucketName=bucket,
        IncludeGlobalServiceEvents=False,
        IsMultiRegionTrail=False,
        TagsList=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_trail(ct, name))

    resp = ct.get_trail(Name=name)
    trail = resp["Trail"]
    assert trail["Name"] == name, f"expected Name={name!r}, got {trail.get('Name')!r}"
    assert trail["S3BucketName"] == bucket, (
        f"expected S3BucketName={bucket!r}, got {trail.get('S3BucketName')!r}"
    )
    assert trail["IncludeGlobalServiceEvents"] is False, (
        f"expected IncludeGlobalServiceEvents=False, got {trail.get('IncludeGlobalServiceEvents')!r}"
    )
    assert trail["IsMultiRegionTrail"] is False, (
        f"expected IsMultiRegionTrail=False, got {trail.get('IsMultiRegionTrail')!r}"
    )
    assert trail["HomeRegion"] == ctx.region, (
        f"expected HomeRegion={ctx.region!r}, got {trail.get('HomeRegion')!r}"
    )

    # Error boundary: a trail name with no matching resource is rejected.
    code, message = _error(lambda: ct.get_trail(Name="sim2real-no-such-trail-987"))
    assert code == "TrailNotFoundException", code
    expected_message = f"Unknown trail: sim2real-no-such-trail-987 for the user: {ctx.account}"
    assert message == expected_message, message


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _bucket_policy(bucket: str, account_id: str) -> dict:
    return {
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
                "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    }


def _create_trail_bucket(ctx):
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-ct-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(_bucket_policy(bucket, account_id)))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket, account_id


def _create_trail_retrying(ct, **kwargs):
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(6):
        try:
            return ct.create_trail(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InsufficientS3BucketPolicyException":
                raise
            last_exc = exc
            time.sleep(3)
    raise last_exc


def _delete_trail(ct, name):
    from botocore.exceptions import ClientError

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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
