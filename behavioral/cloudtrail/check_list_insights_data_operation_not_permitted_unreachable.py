"""list-insights-data-operation-not-permitted-unreachable."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-insights-data-operation-not-permitted-unreachable"
GROUP = "negative-classes"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListInsightsData on a trail that never had Insights enabled returns an empty Events list
    rather than OperationNotPermittedException, and GetInsightSelectors confirms Insights is off."""
    # OperationNotPermittedException applies to a member account reading an organization trail,
    # which a single standalone account cannot construct.
    ct = ctx.client("cloudtrail")
    trail = _create_trail(ctx)

    now = datetime.now(timezone.utc)
    start, end = now - timedelta(hours=1), now

    before = ct.list_insights_data(
        InsightSource=trail["arn"], DataType="InsightsEvents", StartTime=start, EndTime=end
    )
    assert "Events" in before, (
        f"ListInsightsData must return an Events list even when Insights was never "
        f"enabled; got keys {sorted(k for k in before if k != 'ResponseMetadata')}"
    )
    assert isinstance(before["Events"], list), f"Events is not a list: {before['Events']!r}"
    assert before["Events"] == [], (
        f"a trail with no Insights selectors must yield no Insights events, got "
        f"{before['Events'][:3]!r}"
    )
    # Confirms the empty list means "Insights never enabled", not "enabled but quiet".
    code, message = _error(lambda: ct.get_insight_selectors(TrailName=trail["name"]))
    assert code == "InsightNotEnabledException", (
        f"expected GetInsightSelectors to report InsightNotEnabledException for a "
        f"freshly created trail, got {code!r}"
    )
    assert message == (
        f"Trail {trail['arn']} does not have Insights enabled. Edit the trail settings to enable "
        "Insights, and then try the operation again."
    ), message


def _error(fn) -> tuple[str, str | None]:
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_trail(ctx) -> dict[str, Any]:
    """Create a trail backed by a fresh S3 bucket with the CloudTrail bucket policy."""
    s3 = ctx.client("s3")
    ct = ctx.client("cloudtrail")
    sts = ctx.client("sts")
    region = ctx.region
    account_id = sts.get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-ct-bkt-").lower().replace("_", "-")

    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )

    def _cleanup_bucket():
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            for o in objs:
                s3.delete_object(Bucket=bucket, Key=o["Key"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
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
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]},
    )

    trail_name = ctx.unique_name("sim2real-ct-trail-")
    deadline = time.monotonic() + 30
    resp = None
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            resp = ct.create_trail(
                Name=trail_name,
                S3BucketName=bucket,
                IncludeGlobalServiceEvents=True,
                TagsList=[{"Key": "sim2real", "Value": CHECK}],
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InsufficientS3BucketPolicyException":
                last_err = e
                time.sleep(2)
                continue
            raise
    if resp is None:
        raise last_err or RuntimeError("create_trail never succeeded")

    ctx.on_cleanup(lambda: ct.delete_trail(Name=trail_name))
    return {"name": trail_name, "arn": resp["TrailARN"], "bucket": bucket}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
