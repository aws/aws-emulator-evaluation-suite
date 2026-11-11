"""add-list-remove-tags-trail."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


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
    # S3's CreateBucket rejects a LocationConstraint for us-east-1 specifically (its default
    # region); this is an S3 API constant, not a pin of the check's own operating region.
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
    """Create a trail (provisioning a policy-ready bucket unless S3BucketName is
    given) and register best-effort teardown of the trail and any bucket made."""
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


CHECK = "add-list-remove-tags-trail"
GROUP = 'tags'
SERVICES = ['cloudtrail']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddTags/ListTags/RemoveTags round-trip tags on a trail, and RemoveTags is per-key."""
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-ct-trail-")
    resp = _create_trail(ctx, ct, s3, name)
    arn = resp["TrailARN"]

    def tags_of(resource_arn: str) -> list[dict]:
        listed = _call(lambda: ct.list_tags(ResourceIdList=[resource_arn]))
        entries = listed.get("ResourceTagList", [])
        if not entries:
            return []
        assert entries[0]["ResourceId"] == resource_arn, (resource_arn, entries[0]["ResourceId"])
        return entries[0].get("TagsList", [])

    assert tags_of(arn) == [], tags_of(arn)

    _call(
        lambda: ct.add_tags(
            ResourceId=arn,
            TagsList=[
                {"Key": "env", "Value": "fidelity"},
                {"Key": "owner", "Value": "test"},
            ],
        )
    )

    current = {t["Key"]: t["Value"] for t in tags_of(arn)}
    assert current == {"env": "fidelity", "owner": "test"}, current

    # AddTags on an existing key overwrites rather than duplicating it.
    _call(
        lambda: ct.add_tags(
            ResourceId=arn, TagsList=[{"Key": "env", "Value": "updated"}]
        )
    )
    current = tags_of(arn)
    assert len(current) == 2, current
    assert {"Key": "env", "Value": "updated"} in current, current

    # RemoveTags only removes the named keys.
    _call(
        lambda: ct.remove_tags(
            ResourceId=arn, TagsList=[{"Key": "env", "Value": "updated"}]
        )
    )
    current = tags_of(arn)
    assert [t["Key"] for t in current] == ["owner"], current

    _call(
        lambda: ct.remove_tags(
            ResourceId=arn, TagsList=[{"Key": "owner", "Value": "test"}]
        )
    )
    assert tags_of(arn) == [], tags_of(arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
