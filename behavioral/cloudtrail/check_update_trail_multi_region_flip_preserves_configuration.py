"""update-trail-multi-region-flip-preserves-configuration."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

# Single-shot bucket emptying is safe: StartLogging is never called, so CloudTrail never
# writes into the bucket.


def _call(fn, retry_codes=(
    "ThrottlingException",
    "MaximumNumberOfTrailsExceededException",
    "ConflictException",
    "InsufficientS3BucketPolicyException",
), attempts=7):
    """Invoke fn(), retrying transient CloudTrail control-plane errors."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in retry_codes and i < attempts - 1:
                last = exc
                time.sleep(2.0 * (i + 1))
                continue
            raise
    raise last


def _create_bucket_only(s3, bucket, region):
    """Create a plain S3 bucket (no CloudTrail policy)."""
    kwargs = {"Bucket": bucket}
    # us-east-1 is S3's own CreateBucket default and is the one region that rejects an
    # explicit LocationConstraint, so it is omitted only there.
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


def _delete_trail(ct, name):
    """Best-effort teardown: stop logging (if on) then delete the trail."""
    try:
        ct.stop_logging(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise
    try:
        _call(lambda: ct.delete_trail(Name=name))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise


def _create_trail(ctx, ct, s3, name, **kwargs):
    """Create a trail, provisioning a policy-ready bucket unless S3BucketName is given."""
    bucket = kwargs.pop("S3BucketName", None)
    if not bucket:
        bucket = ctx.unique_name("sim2real-behav-ct-bkt-").lower()
        account = ctx.client("sts").get_caller_identity()["Account"]
        _create_trail_bucket(s3, bucket, ctx.region, account)
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    params = {"Name": name, "S3BucketName": bucket}
    params.update(kwargs)
    resp = _call(lambda: ct.create_trail(**params))
    ctx.on_cleanup(lambda: _delete_trail(ct, name))
    return resp


CHECK = "update-trail-multi-region-flip-preserves-configuration"
GROUP = 'trail-lifecycle'
SERVICES = ['cloudtrail']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Flipping IsMultiRegionTrail False -> True -> False changes only that flag: HomeRegion, ARN,
    S3 destination, event selectors and tags survive, and the trail is listed exactly once.

    Reference: https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_UpdateTrail.html
    """
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")

    name = ctx.unique_name("sim2real-behav-ct-trail-")
    created = _create_trail(ctx, ct, s3, name, S3KeyPrefix="mr-flip")
    minted_arn = created["TrailARN"]
    assert minted_arn.endswith(f":trail/{name}"), minted_arn

    baseline = _call(lambda: ct.get_trail(Name=name))["Trail"]
    home_region = baseline["HomeRegion"]
    assert home_region == ctx.region, (home_region, ctx.region)
    assert not baseline.get("IsMultiRegionTrail"), baseline.get("IsMultiRegionTrail")
    bucket = baseline["S3BucketName"]
    assert baseline["S3KeyPrefix"] == "mr-flip", baseline.get("S3KeyPrefix")

    # Management-only selector: no data events, so the trail incurs no event charges.
    selectors = [
        {
            "Name": "sim2real-management-write-events",
            "FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Management"]},
                {"Field": "readOnly", "Equals": ["false"]},
            ],
        }
    ]
    _call(lambda: ct.put_event_selectors(TrailName=name, AdvancedEventSelectors=selectors))
    expected_tags = {"sim2real-purpose": "mr-flip", "sim2real-owner": "simparity"}
    _call(
        lambda: ct.add_tags(
            ResourceId=minted_arn,
            TagsList=[{"Key": k, "Value": v} for k, v in expected_tags.items()],
        )
    )

    def assert_invariants(*, multi_region: bool):
        """Everything except IsMultiRegionTrail must be identical to the baseline."""
        trail = _call(lambda: ct.get_trail(Name=name))["Trail"]
        assert trail["TrailARN"] == minted_arn, trail["TrailARN"]
        assert trail["HomeRegion"] == home_region, (trail["HomeRegion"], home_region)
        assert trail["S3BucketName"] == bucket, trail["S3BucketName"]
        assert trail["S3KeyPrefix"] == "mr-flip", trail.get("S3KeyPrefix")
        assert trail["Name"] == name, trail["Name"]
        assert bool(trail.get("IsMultiRegionTrail")) is multi_region, (
            trail.get("IsMultiRegionTrail"),
            multi_region,
        )
        # The ARN's own region segment must not have moved either.
        assert minted_arn.split(":")[3] == home_region, minted_arn

        got = _call(lambda: ct.get_event_selectors(TrailName=name))
        assert got["TrailARN"] == minted_arn, got["TrailARN"]
        assert got["AdvancedEventSelectors"] == selectors, got["AdvancedEventSelectors"]

        listed = _call(lambda: ct.list_tags(ResourceIdList=[minted_arn]))["ResourceTagList"]
        assert len(listed) == 1, listed
        assert listed[0]["ResourceId"] == minted_arn, listed[0]["ResourceId"]
        assert {t["Key"]: t["Value"] for t in listed[0]["TagsList"]} == expected_tags, listed[0]

        # Exactly one entry, not one per shadow region.
        described = [
            t
            for t in _call(lambda: ct.describe_trails(trailNameList=[minted_arn]))["trailList"]
            if t["TrailARN"] == minted_arn
        ]
        assert len(described) == 1, f"expected 1 DescribeTrails entry, got {len(described)}: {described}"
        assert described[0]["HomeRegion"] == home_region, described[0]["HomeRegion"]
        assert bool(described[0].get("IsMultiRegionTrail")) is multi_region, described[0]

        summaries = []
        token = None
        for _ in range(20):
            page = _call(
                lambda: ct.list_trails(NextToken=token) if token else ct.list_trails()
            )
            summaries.extend(page.get("Trails", []))
            token = page.get("NextToken")
            if not token:
                break
        mine = [t for t in summaries if t["TrailARN"] == minted_arn]
        assert len(mine) == 1, f"expected 1 ListTrails entry, got {len(mine)}: {mine}"
        assert mine[0]["Name"] == name, mine[0]["Name"]
        if "HomeRegion" in mine[0]:
            assert mine[0]["HomeRegion"] == home_region, mine[0]["HomeRegion"]
        return trail

    assert_invariants(multi_region=False)

    pre_flip_arn = _call(lambda: ct.get_trail(Name=name))["Trail"]["TrailARN"]
    assert pre_flip_arn == minted_arn, (pre_flip_arn, minted_arn)
    flipped = _call(lambda: ct.update_trail(Name=name, IsMultiRegionTrail=True))
    assert flipped["TrailARN"] == minted_arn, flipped["TrailARN"]
    assert flipped["IsMultiRegionTrail"] is True, flipped.get("IsMultiRegionTrail")
    assert_invariants(multi_region=True)

    pre_restore_arn = _call(lambda: ct.get_trail(Name=name))["Trail"]["TrailARN"]
    assert pre_restore_arn == minted_arn, (pre_restore_arn, minted_arn)
    restored = _call(lambda: ct.update_trail(Name=name, IsMultiRegionTrail=False))
    assert restored["TrailARN"] == minted_arn, restored["TrailARN"]
    assert restored["IsMultiRegionTrail"] is False, restored.get("IsMultiRegionTrail")
    final = assert_invariants(multi_region=False)
    # The selector applied before the flips is still recognised as a custom selector, so
    # the round trip did not quietly reset the trail to its defaults.
    assert final["HasCustomEventSelectors"] is True, final.get("HasCustomEventSelectors")
    assert final["IncludeGlobalServiceEvents"] == baseline["IncludeGlobalServiceEvents"], (
        final.get("IncludeGlobalServiceEvents"),
        baseline.get("IncludeGlobalServiceEvents"),
    )
    assert final["LogFileValidationEnabled"] == baseline["LogFileValidationEnabled"], (
        final.get("LogFileValidationEnabled"),
        baseline.get("LogFileValidationEnabled"),
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
