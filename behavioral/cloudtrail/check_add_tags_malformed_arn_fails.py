"""add-tags-malformed-arn-fails."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """(Error.Code, Error.Message) for the ClientError fn() raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


def _bucket_policy(bucket, account_id):
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
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-ct-").lower().replace("_", "-")
    # us-east-1 literal: S3's own CreateBucket quirk (LocationConstraint must be omitted
    # there), not a pin of this check's operating region.
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
    return bucket


def _create_trail_retrying(ct, **kwargs):
    last_exc = None
    for _ in range(6):
        try:
            return ct.create_trail(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InsufficientS3BucketPolicyException":
                raise
            last_exc = exc
            time.sleep(3)
    raise last_exc


def _delete_trail(ct, name):
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


CHECK = "add-tags-malformed-arn-fails"
GROUP = 'overly-permissive'
SERVICES = ['cloudtrail']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddTags/ListTags reject a non-ARN or non-CloudTrail ResourceId with
    CloudTrailARNInvalidException, while a real trail ARN (positive control) takes the tag and
    keeps it unchanged across the rejected calls."""
    ct = ctx.client("cloudtrail")
    bucket = _create_trail_bucket(ctx)
    name = ctx.unique_name("sim2real-behav-ct-trail-")
    trail_arn = _create_trail_retrying(ct, Name=name, S3BucketName=bucket)["TrailARN"]
    ctx.on_cleanup(lambda: _delete_trail(ct, name))

    valid_tag = [{"Key": "env", "Value": "fidelity"}]
    ct.add_tags(ResourceId=trail_arn, TagsList=valid_tag)
    control = ct.list_tags(ResourceIdList=[trail_arn])["ResourceTagList"][0]["TagsList"]
    assert control == valid_tag, (
        f"positive control: expected the well-formed trail ARN to carry {valid_tag!r} after "
        f"AddTags, ListTags returned {control!r}"
    )

    malformed_cases = [
        ("not-an-arn", "not a syntactically valid ARN at all"),
        ("arn:aws:s3:::sim2real-behav-not-cloudtrail", "a well-formed ARN for the wrong service"),
    ]
    for resource_id, description in malformed_cases:
        code, message = _error(lambda rid=resource_id: ct.add_tags(ResourceId=rid, TagsList=valid_tag))
        assert code == "CloudTrailARNInvalidException", (
            f"AddTags(ResourceId={resource_id!r}) [{description}]: expected "
            f"CloudTrailARNInvalidException, got {code!r}"
        )
        assert message == f"The ARN {resource_id} is invalid.", (
            f"AddTags(ResourceId={resource_id!r}) [{description}]: message {message!r}"
        )

    code, message = _error(lambda: ct.list_tags(ResourceIdList=["not-an-arn"]))
    assert code == "CloudTrailARNInvalidException", (
        f"ListTags(ResourceIdList=['not-an-arn']): expected CloudTrailARNInvalidException, "
        f"got {code!r}"
    )
    assert message == "The ARN not-an-arn is invalid.", (
        f"ListTags(ResourceIdList=['not-an-arn']): message {message!r}"
    )

    unchanged = ct.list_tags(ResourceIdList=[trail_arn])["ResourceTagList"][0]["TagsList"]
    assert unchanged == valid_tag, (
        f"the malformed-ARN calls left the well-formed trail's tags as {unchanged!r}, "
        f"expected the positive control's {valid_tag!r} to survive unchanged"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
