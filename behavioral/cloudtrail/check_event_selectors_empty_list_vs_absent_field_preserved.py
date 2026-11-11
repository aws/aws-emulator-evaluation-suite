"""event-selectors-empty-list-vs-absent-field-preserved."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "event-selectors-empty-list-vs-absent-field-preserved"
GROUP = "representation"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After a PutEventSelectors/GetEventSelectors round trip, a selector with an explicit
    empty DataResources list and one that omits the field both come back with DataResources: []."""
    ct = ctx.client("cloudtrail")
    trail = _create_trail_with_bucket(ctx)

    selector_with_empty_list = {
        "ReadWriteType": "ReadOnly",
        "IncludeManagementEvents": True,
        "DataResources": [],
    }
    selector_without_field = {
        "ReadWriteType": "WriteOnly",
        "IncludeManagementEvents": True,
    }

    ct.put_event_selectors(
        TrailName=trail["name"],
        EventSelectors=[selector_with_empty_list, selector_without_field],
    )

    got = ct.get_event_selectors(TrailName=trail["name"])
    by_rwt = {s["ReadWriteType"]: s for s in got["EventSelectors"]}

    # CloudTrail does not preserve empty-vs-absent: both normalize to an empty list.
    assert "ReadOnly" in by_rwt and "WriteOnly" in by_rwt, got["EventSelectors"]
    assert "DataResources" in by_rwt["ReadOnly"], by_rwt["ReadOnly"]
    assert by_rwt["ReadOnly"]["DataResources"] == [], by_rwt["ReadOnly"]["DataResources"]
    assert "DataResources" in by_rwt["WriteOnly"], by_rwt["WriteOnly"]
    assert by_rwt["WriteOnly"]["DataResources"] == [], by_rwt["WriteOnly"]["DataResources"]


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
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )

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
