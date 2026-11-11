"""event-selectors-quota-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "event-selectors-quota-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudtrail"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutEventSelectors with 6 EventSelectors answers InvalidEventSelectorsException "Specify a valid number of
    selectors (1 to 5) for your trail" and leaves a non-default WriteOnly baseline unchanged; a single valid
    ReadOnly selector then applies."""
    ct = ctx.client("cloudtrail")
    trail = _create_trail_with_bucket(ctx)

    # A NON-DEFAULT baseline: a freshly created trail's own default selector set is
    # already {"ReadWriteType": "All", ...}, so comparing the post-rejection read against
    # that default cannot tell "the write was rejected and nothing changed" apart from "the
    # write was rejected and the trail was reset to its default". WriteOnly is neither the
    # default nor either payload used below.
    ct.put_event_selectors(
        TrailName=trail["name"],
        EventSelectors=[{"ReadWriteType": "WriteOnly", "IncludeManagementEvents": True}],
    )
    baseline = ct.get_event_selectors(TrailName=trail["name"])["EventSelectors"]
    assert baseline[0]["ReadWriteType"] == "WriteOnly", (
        f"the non-default baseline did not take effect: {baseline!r}"
    )

    too_many = [{"ReadWriteType": "All", "IncludeManagementEvents": True} for _ in range(6)]
    code, message = _error(
        lambda: ct.put_event_selectors(TrailName=trail["name"], EventSelectors=too_many)
    )
    assert code == "InvalidEventSelectorsException", (
        f"expected InvalidEventSelectorsException for a 6-element EventSelectors list, got {code!r}"
    )
    assert message == "Specify a valid number of selectors (1 to 5) for your trail", message

    unchanged = ct.get_event_selectors(TrailName=trail["name"])["EventSelectors"]
    assert unchanged == baseline, (
        f"the rejected write changed the live configuration: baseline={baseline!r} "
        f"after={unchanged!r}"
    )

    valid_one = [{"ReadWriteType": "ReadOnly", "IncludeManagementEvents": True}]
    ct.put_event_selectors(TrailName=trail["name"], EventSelectors=valid_one)
    applied = ct.get_event_selectors(TrailName=trail["name"])["EventSelectors"]
    assert len(applied) == 1, (
        f"expected exactly 1 selector after a valid PutEventSelectors, got {applied!r}"
    )
    assert applied[0]["ReadWriteType"] == "ReadOnly", (
        f"expected ReadWriteType='ReadOnly' after the valid PutEventSelectors, got {applied!r}"
    )


def _error(fn):
    """The exact AWS (Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success
    raises, so a target that accepts input AWS rejects fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected PutEventSelectors to be rejected with InvalidEventSelectorsException, "
        f"but it SUCCEEDED and returned {result!r}"
    )


def _create_trail_with_bucket(ctx):
    import json

    s3 = ctx.client("s3")
    ct = ctx.client("cloudtrail")
    region = ctx.region
    bucket = ctx.unique_name("sim2real-ct-quota-b-").lower()[:63]
    if region == "us-east-1":
        # us-east-1 is S3's own default region; CreateBucketConfiguration.LocationConstraint
        # must be omitted there or S3 rejects it, regardless of ctx.region.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    trail_name = ctx.unique_name("sim2real-ct-quota-t-")
    trail_arn = f"arn:aws:cloudtrail:{region}:{account_id}:trail/{trail_name}"
    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailAclCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": f"arn:aws:s3:::{bucket}",
                    "Condition": {"StringEquals": {"aws:SourceArn": trail_arn}},
                },
                {
                    "Sid": "AWSCloudTrailWrite",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                    "Condition": {
                        "StringEquals": {
                            "s3:x-amz-acl": "bucket-owner-full-control",
                            "aws:SourceArn": trail_arn,
                        }
                    },
                },
            ],
        }
    )
    s3.put_bucket_policy(Bucket=bucket, Policy=policy)
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]}
    )
    resp = ct.create_trail(
        Name=trail_name,
        S3BucketName=bucket,
        TagsList=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_trail_if_exists(ctx, trail_name))
    return {"name": trail_name, "arn": resp["TrailARN"], "bucket": bucket}


def _delete_trail_if_exists(ctx, trail_name: str) -> None:
    ct = ctx.client("cloudtrail")
    try:
        ct.delete_trail(Name=trail_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
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
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
