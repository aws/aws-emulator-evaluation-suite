"""tag-value-unicode-and-empty-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-value-unicode-and-empty-round-trip"
GROUP = "representation"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode tag values round-trip byte-for-byte on a CloudTrail trail, and a tag with
    an omitted Value comes back through AddTags/ListTags as an empty string, not dropped
    and not carrying some other sentinel."""
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    region = ctx.region
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-ct-tag-b-").lower()
    _create_trail_bucket(s3, bucket, region, account_id)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    name = ctx.unique_name("sim2real-ct-tag-t-")
    created = _call(lambda: ct.create_trail(Name=name, S3BucketName=bucket))
    ctx.on_cleanup(lambda: _delete_trail(ct, name))
    arn = created["TrailARN"]

    # Symbol-category codepoints such as emoji are rejected by CloudTrail's tag
    # validation (InvalidTagParameterException) -- the unicode coverage here sticks to
    # Letter-category codepoints (accented Latin, CJK, Arabic) which are accepted.
    unicode_value = "日本語-café-مرحبا"
    unicode_key = "sim2real-unicode-key-éè"
    novalue_key = "sim2real-no-value-key"
    _call(
        lambda: ct.add_tags(
            ResourceId=arn,
            TagsList=[
                {"Key": unicode_key, "Value": unicode_value},
                {"Key": novalue_key},  # Value intentionally omitted, not ""
            ],
        )
    )

    resp = _call(lambda: ct.list_tags(ResourceIdList=[arn]))
    tag_lists = [entry["TagsList"] for entry in resp["ResourceTagList"] if entry["ResourceId"] == arn]
    assert len(tag_lists) == 1, f"expected exactly one ResourceTagList entry for {arn}, got {tag_lists}"
    by_key = {t["Key"]: t for t in tag_lists[0]}

    assert unicode_key in by_key and novalue_key in by_key, (
        f"expected keys {unicode_key!r} and {novalue_key!r} in {sorted(by_key)}"
    )
    assert by_key[unicode_key]["Value"] == unicode_value, (
        f"unicode tag value mangled: {by_key[unicode_key]['Value']!r} != {unicode_value!r}"
    )
    # A tag added without a Value comes back with Value="" (measured on real AWS), not
    # dropped from the response and not carrying any other sentinel.
    assert by_key[novalue_key].get("Value") == "", (
        f"tag Value omitted at creation came back as {by_key[novalue_key].get('Value')!r} instead of ''"
    )


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


def _create_trail_bucket(s3, bucket: str, region: str, account_id: str) -> None:
    """Create an S3 bucket (idempotently) with the policy CloudTrail needs to deliver logs."""
    kwargs = {"Bucket": bucket}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise
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


def _empty_and_delete_bucket(s3, bucket: str) -> None:
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
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_trail(ct, name: str) -> None:
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
