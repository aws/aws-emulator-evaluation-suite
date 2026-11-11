"""update-event-data-store-during-active-ingestion-wrong-state-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-event-data-store-during-active-ingestion-wrong-state-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudtrail"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrail rejects an S3 bucket that does not exist rather than silently creating the trail.

    No trail is left behind, and the identical call against a real bucket with the CloudTrail
    delivery policy succeeds and is discoverable via DescribeTrails.
    """
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    nonexistent_bucket = ctx.unique_name("sim2real-ct-missing-").lower()
    bad_name = ctx.unique_name("sim2real-trail-badbucket-")
    code, message = _error(
        lambda: ct.create_trail(
            Name=bad_name, S3BucketName=nonexistent_bucket, IsMultiRegionTrail=False
        )
    )
    assert code == "S3BucketDoesNotExistException", f"expected S3BucketDoesNotExistException, got {code}"
    expected_message = f"S3 bucket {nonexistent_bucket} does not exist!"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    trails = ct.describe_trails(trailNameList=[], includeShadowTrails=False)["trailList"]
    assert all(t["Name"] != bad_name for t in trails), "rejected trail was created anyway"

    # Positive control: the identical call against a real, correctly-configured
    # bucket succeeds.
    bucket = _create_trail_bucket(ctx, s3, account_id)
    good_name = ctx.unique_name("sim2real-trail-goodbucket-")
    created = ct.create_trail(Name=good_name, S3BucketName=bucket, IsMultiRegionTrail=False)
    ctx.on_cleanup(lambda: ct.delete_trail(Name=good_name))
    assert created["S3BucketName"] == bucket, (
        f"expected CreateTrail to echo S3BucketName {bucket!r}, got {created['S3BucketName']!r}"
    )

    # Independent read at the destination: the trail is actually discoverable
    # (not just echoed back by the mutating call itself), proving the earlier
    # rejection was conditioned on the bucket precondition rather than a
    # blanket failure of trail creation.
    good_trails = ct.describe_trails(trailNameList=[good_name])["trailList"]
    assert len(good_trails) == 1, f"expected exactly one trail named {good_name!r}, got {good_trails}"
    assert good_trails[0]["S3BucketName"] == bucket, (
        f"describe_trails S3BucketName {good_trails[0]['S3BucketName']!r} != {bucket!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (Error Code, Error Message). An unexpected SUCCESS raises, because
    an emulator accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it succeeded: {result!r}")


def _create_trail_bucket(ctx, s3, account_id: str) -> str:
    bucket = ctx.unique_name("sim2real-ct-real-").lower()
    # us-east-1 is a literal here because S3's CreateBucket rejects an explicit
    # LocationConstraint for that region specifically, not because this resource is pinned to it.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _empty_and_delete():
        # CloudTrail delivers into the bucket as soon as the trail exists, so empty it first.
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for obj in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"], VersionId=obj["VersionId"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete)

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
                "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    return bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
