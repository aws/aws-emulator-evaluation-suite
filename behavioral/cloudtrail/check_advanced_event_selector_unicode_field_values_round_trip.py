"""advanced-event-selector-unicode-field-values-round-trip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "advanced-event-selector-unicode-field-values-round-trip"
GROUP = "representation"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Advanced event selector Name and field values containing unicode
    characters survive a PutEventSelectors/GetEventSelectors round trip
    unchanged at the byte level."""
    ct = ctx.client("cloudtrail")
    trail = _create_trail_with_bucket(ctx)

    advanced_selectors = [
        {
            "Name": "sel-\u00fcn\u00efc\u00f8d\u00e9-\u65e5\u672c\u8a9e-\u2602\U0001f389",
            "FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Data"]},
                {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
                {"Field": "eventName", "Equals": ["\u00dcn\u00efc\u00f8d\u00e9-\u00c9v\u00e9nement-\u2605"]},
            ],
        }
    ]

    put = ct.put_event_selectors(TrailName=trail["name"], AdvancedEventSelectors=advanced_selectors)
    put_selectors = put["AdvancedEventSelectors"]
    assert _normalize(put_selectors) == _normalize(advanced_selectors), (
        f"PutEventSelectors echoed mangled unicode: expected {_normalize(advanced_selectors)!r}, "
        f"got {_normalize(put_selectors)!r}"
    )

    got = ct.get_event_selectors(TrailName=trail["name"])
    got_selectors = got["AdvancedEventSelectors"]
    assert len(got_selectors) == len(advanced_selectors), (
        f"expected {len(advanced_selectors)} advanced selector(s) back from GetEventSelectors, "
        f"got {len(got_selectors)}: {got_selectors!r}"
    )
    assert _normalize(got_selectors) == _normalize(advanced_selectors), (
        f"GetEventSelectors returned different unicode content: expected "
        f"{_normalize(advanced_selectors)!r}, got {_normalize(got_selectors)!r}"
    )


def _normalize(selectors):
    # CloudTrail is free to return FieldSelectors in a different order than
    # they were submitted (e.g. reordered by Field name); the set of
    # (Field, sorted value-lists) pairs per selector is what must survive the
    # round trip byte-for-byte, not list positional order.
    normalized = []
    for sel in selectors:
        field_selectors = tuple(
            sorted(
                (
                    fs["Field"],
                    tuple(sorted(fs.get("Equals", []))),
                )
                for fs in sel["FieldSelectors"]
            )
        )
        normalized.append((sel["Name"], field_selectors))
    return sorted(normalized)


def _create_trail_with_bucket(ctx):
    import json

    s3 = ctx.client("s3")
    ct = ctx.client("cloudtrail")
    region = ctx.region
    bucket = ctx.unique_name("sim2real-ct-aes-b-").lower()[:63]
    # us-east-1 is S3's CreateBucket special case: it rejects an explicit
    # LocationConstraint. ctx.region still drives every other decision here.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-behav", "Value": "true"}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    trail_name = ctx.unique_name("sim2real-ct-aes-t-")
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
    resp = ct.create_trail(
        Name=trail_name,
        S3BucketName=bucket,
        TagsList=[{"Key": "sim2real-behav", "Value": "true"}],
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
