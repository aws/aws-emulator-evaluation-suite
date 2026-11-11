"""event-selectors-exceeds-limit-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "event-selectors-exceeds-limit-rejected"
GROUP = "representation"
SERVICES = ["cloudtrail"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutEventSelectors with 6 selectors answers InvalidEventSelectorsException "Specify a valid number of
    selectors (1 to 5) for your trail" and leaves a non-default ReadOnly baseline unchanged (so a reset to the
    default would show); a valid 2-selector update then reads back exactly."""
    ct = ctx.client("cloudtrail")
    trail = _create_trail_with_bucket(ctx)

    baseline = [{"ReadWriteType": "ReadOnly", "IncludeManagementEvents": True}]
    ct.put_event_selectors(TrailName=trail["name"], EventSelectors=baseline)
    baseline_got = ct.get_event_selectors(TrailName=trail["name"])["EventSelectors"]
    # CloudTrail normalizes an omitted DataResources to an explicit empty list in the
    # response, so compare against the baseline plus that normalization rather than
    # the bare request shape.
    expected_baseline = [
        {**baseline[0], "DataResources": [], "ExcludeManagementEventSources": []}
    ]
    assert baseline_got == expected_baseline, baseline_got
    assert expected_baseline[0]["ReadWriteType"] != "All", (
        "the baseline must differ from a fresh trail's default (ReadWriteType='All') or the "
        "unchanged-after-rejection assertion below cannot detect a reset-to-default target"
    )

    too_many = [
        {"ReadWriteType": "All", "IncludeManagementEvents": (i % 2 == 0)} for i in range(6)
    ]
    code, message = _error(
        lambda: ct.put_event_selectors(TrailName=trail["name"], EventSelectors=too_many)
    )
    assert code == "InvalidEventSelectorsException", code
    assert message == "Specify a valid number of selectors (1 to 5) for your trail", message

    unchanged = ct.get_event_selectors(TrailName=trail["name"])["EventSelectors"]
    assert unchanged == expected_baseline, unchanged

    valid_update = [
        {"ReadWriteType": "ReadOnly", "IncludeManagementEvents": True},
        {"ReadWriteType": "WriteOnly", "IncludeManagementEvents": True},
    ]
    ct.put_event_selectors(TrailName=trail["name"], EventSelectors=valid_update)
    after_valid = ct.get_event_selectors(TrailName=trail["name"])["EventSelectors"]
    expected_valid = [
        {**s, "DataResources": [], "ExcludeManagementEventSources": []} for s in valid_update
    ]
    assert after_valid == expected_valid, after_valid


def _error(fn):
    """The exact AWS (Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises,
    so a target that accepts the over-limit selector list fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"PutEventSelectors with too many selectors unexpectedly SUCCEEDED: {result!r}"
    )


def _account_id(ctx: Any) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_trail_with_bucket(ctx: Any) -> dict[str, str]:
    s3 = ctx.client("s3")
    ct = ctx.client("cloudtrail")
    bucket = ctx.unique_name("sim2real-ct-b-").lower().replace("_", "-")
    trail_name = ctx.unique_name("sim2real-ct-trail-")
    account_id = _account_id(ctx)
    trail_arn = f"arn:aws:cloudtrail:{ctx.region}:{account_id}:trail/{trail_name}"

    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )

    def _cleanup_bucket() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            )
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup_bucket)

    policy = {
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
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))

    resp = _create_trail_with_retry(ct, trail_name, bucket)
    ctx.on_cleanup(lambda: ct.delete_trail(Name=trail_name))
    return {"name": trail_name, "arn": resp["TrailARN"], "bucket": bucket}


def _create_trail_with_retry(ct: Any, trail_name: str, bucket: str, attempts: int = 5) -> dict:
    last_exc = None
    for _ in range(attempts):
        try:
            return ct.create_trail(
                Name=trail_name,
                S3BucketName=bucket,
                TagsList=[{"Key": "sim2real", "Value": CHECK}],
            )
        except ct.exceptions.InsufficientS3BucketPolicyException as exc:  # policy propagation
            last_exc = exc
            time.sleep(5.0)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
