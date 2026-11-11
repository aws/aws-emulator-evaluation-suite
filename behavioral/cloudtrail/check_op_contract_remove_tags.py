"""op-contract-remove-tags."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-remove-tags"
GROUP = "error-semantics"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemoveTags removes exactly the named tag while leaving others; a malformed ResourceId is rejected."""
    ct = ctx.client("cloudtrail")
    bucket, _account_id = _create_trail_bucket(ctx)
    name = ctx.unique_name("sim2real-ct-trail-")
    trail_arn = _create_trail_retrying(ct, Name=name, S3BucketName=bucket)["TrailARN"]
    ctx.on_cleanup(lambda: _delete_trail(ct, name))

    ct.add_tags(
        ResourceId=trail_arn,
        TagsList=[{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "sim2real"}],
    )

    ct.remove_tags(ResourceId=trail_arn, TagsList=[{"Key": "env", "Value": "test"}])

    remaining = ct.list_tags(ResourceIdList=[trail_arn])["ResourceTagList"][0]["TagsList"]
    assert remaining == [{"Key": "owner", "Value": "sim2real"}], remaining

    # Error boundary: a malformed (non-ARN) ResourceId is rejected, and the trail's tags are
    # left unchanged.
    code, message = _error(
        lambda: ct.remove_tags(
            ResourceId="not-a-valid-arn", TagsList=[{"Key": "owner", "Value": "sim2real"}]
        )
    )
    assert code == "CloudTrailARNInvalidException", code
    assert message == "The ARN not-a-valid-arn is invalid.", message

    still_there = ct.list_tags(ResourceIdList=[trail_arn])["ResourceTagList"][0]["TagsList"]
    assert still_there == [{"Key": "owner", "Value": "sim2real"}], still_there


def _error(fn):
    """Call fn() and return its (Error.Code, Error.Message); raise if the call succeeds."""
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
    # S3 CreateBucket in us-east-1 rejects an explicit LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(_bucket_policy(bucket, account_id)))

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
