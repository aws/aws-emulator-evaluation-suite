"""event-selectors-unicode-field-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-selectors-unicode-field-round-trip"
GROUP = "representation"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode strings in AdvancedEventSelectors field values survive PutEventSelectors/GetEventSelectors unchanged."""
    trail_name, bucket_name = _create_trail_with_bucket(ctx)
    ct = ctx.client("cloudtrail")

    selectors = [
        {
            "Name": "Unicode selector \u65e5\u672c\u8a9e \u2603\ufe0f",
            "FieldSelectors": [
                # eventName/userIdentity.arn are only usable with eventCategory=Management
                # for EVENT DATA STORES, not trails ("field is not allowed when eventCategory
                # equals Management" on a trail). For trails, eventName IS supported for
                # eventCategory=Data (which also requires resources.type), so use that
                # category to carry the unicode payload instead.
                {"Field": "eventCategory", "Equals": ["Data"]},
                {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
                {
                    "Field": "eventName",
                    "Equals": [
                        "\u65e5\u672c\u8a9e\u30c6\u30b9\u30c8-\U0001f389-\u00dc\u00ef\u00c7\u00f6d\u00e9",
                        "AnotherValue-\u0395\u03bb\u03bb\u03b7\u03bd\u03b9\u03ba\u03ac",
                    ],
                },
            ],
        }
    ]

    put_resp = ct.put_event_selectors(TrailName=trail_name, AdvancedEventSelectors=selectors)
    assert _normalize_selectors(put_resp["AdvancedEventSelectors"]) == _normalize_selectors(selectors), (
        f"PutEventSelectors response mangled unicode selectors: {put_resp['AdvancedEventSelectors']!r}"
    )

    get_resp = ct.get_event_selectors(TrailName=trail_name)
    assert _normalize_selectors(get_resp["AdvancedEventSelectors"]) == _normalize_selectors(selectors), (
        f"GetEventSelectors returned different unicode content: {get_resp['AdvancedEventSelectors']!r}"
    )
    # sanity: the exact unicode bytes must be present, not escaped/mangled/normalized
    by_field = {fs["Field"]: fs for fs in get_resp["AdvancedEventSelectors"][0]["FieldSelectors"]}
    assert "\U0001f389" in by_field["eventName"]["Equals"][0], (
        f"astral-plane codepoint dropped or mangled in round trip: {by_field['eventName']['Equals'][0]!r}"
    )


def _normalize_selectors(selectors: list[dict]) -> list[dict]:
    """FieldSelectors order is not guaranteed by the API; compare by Field name,
    not positionally."""
    return [
        {
            "Name": sel["Name"],
            "FieldSelectors": {fs["Field"]: fs for fs in sel["FieldSelectors"]},
        }
        for sel in selectors
    ]


def _create_trail_with_bucket(ctx) -> tuple[str, str]:
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    s3 = ctx.client("s3")
    ct = ctx.client("cloudtrail")

    bucket_name = ctx.unique_name("sim2real-ct-sel-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )

    def _cleanup_bucket():
        objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket_name, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket_name)

    ctx.on_cleanup(_cleanup_bucket)
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]},
    )

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket_name}",
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/*",
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))

    trail_name = ctx.unique_name("sim2real-ct-trail-")
    resp = _create_trail_retrying(ct, Name=trail_name, S3BucketName=bucket_name)
    ctx.on_cleanup(lambda: ct.delete_trail(Name=trail_name))
    ct.add_tags(
        ResourceId=resp["TrailARN"],
        TagsList=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )

    return trail_name, bucket_name


def _create_trail_retrying(ct, **kwargs):
    """S3 bucket policy propagation can lag briefly behind CreateTrail's policy
    check; retry on that specific error with a bounded deadline instead of
    guessing a fixed delay."""
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
