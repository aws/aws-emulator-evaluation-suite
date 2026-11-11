"""trail-tags-unicode-and-empty-value-preserved."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "trail-tags-unicode-and-empty-value-preserved"
GROUP = "representation"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A unicode tag pair round-trips exactly and a tag added without a Value lists as an empty
    string; RemoveTags then drops only the named key."""
    ct = ctx.client("cloudtrail")
    trail = _create_trail_with_bucket(ctx)

    # CloudTrail tags allow Unicode letters, numbers and punctuation; Symbol-category code
    # points such as emoji are rejected with InvalidTagParameterException.
    key_no_value = "\u00fcn\u00efc\u00f8d\u00e9-key-noval"
    key_unicode = "\u65e5\u672c\u8a9e\u30ad\u30fc"
    value_unicode = "\u65e5\u672c\u8a9e\u5024-\u00e9v\u00e9nement"

    ct.add_tags(
        ResourceId=trail["arn"],
        TagsList=[{"Key": key_no_value}, {"Key": key_unicode, "Value": value_unicode}],
    )

    tags_map = _tags_for(ct, trail["arn"])
    assert tags_map[key_no_value] == "", (
        f"valueless tag {key_no_value!r} came back as {tags_map[key_no_value]!r}, expected ''"
    )
    assert tags_map[key_unicode] == value_unicode, (
        f"unicode tag value mangled: expected {value_unicode!r}, got {tags_map[key_unicode]!r}"
    )

    ct.remove_tags(ResourceId=trail["arn"], TagsList=[{"Key": key_no_value}])

    tags_map_after = _tags_for(ct, trail["arn"])
    assert key_no_value not in tags_map_after, (
        f"RemoveTags left {key_no_value!r} present as {tags_map_after.get(key_no_value)!r}, expected absent"
    )
    assert tags_map_after[key_unicode] == value_unicode, (
        f"unicode tag value did not survive RemoveTags of an unrelated key: "
        f"expected {value_unicode!r}, got {tags_map_after[key_unicode]!r}"
    )


def _tags_for(ct, resource_arn: str) -> dict:
    resp = ct.list_tags(ResourceIdList=[resource_arn])
    for entry in resp["ResourceTagList"]:
        if entry["ResourceId"] == resource_arn:
            return {t["Key"]: t.get("Value", "") for t in entry["TagsList"]}
    return {}


def _create_trail_with_bucket(ctx):
    import json

    s3 = ctx.client("s3")
    ct = ctx.client("cloudtrail")
    region = ctx.region
    bucket = ctx.unique_name("sim2real-ct-tag-b-").lower()[:63]
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for --
    # an S3 API quirk, not a pin to that region; ctx.region drives everything else.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    trail_name = ctx.unique_name("sim2real-ct-tag-t-")
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
    resp = ct.create_trail(Name=trail_name, S3BucketName=bucket)
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
