"""put-insight-selectors-unsupported-type-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-insight-selectors-unsupported-type-rejected"
GROUP = "negative-classes"
SERVICES = ["cloudtrail"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutInsightSelectors rejects an out-of-range InsightType value with
    InvalidInsightSelectorsException; no selector is persisted, and a
    supported InsightType on the same trail succeeds."""
    ct = ctx.client("cloudtrail")
    trail = _create_trail(ctx)

    code, message = _error(
        lambda: ct.put_insight_selectors(
            TrailName=trail["name"], InsightSelectors=[{"InsightType": "NotARealInsightType"}]
        ),
        context="PutInsightSelectors with InsightType=NotARealInsightType",
    )
    assert code == "InvalidInsightSelectorsException", (
        f"expected InvalidInsightSelectorsException for an unsupported InsightType, got {code!r}"
    )
    assert message == (
        "The provided value is not a valid Insights type: NotARealInsightType. Valid Insight "
        "types are: ApiCallRateInsight and ApiErrorRateInsight. Verify your input and then try "
        "again."
    ), message

    # Effect absent: no insight selectors were persisted on the trail.
    not_enabled_code, not_enabled_message = _error(
        lambda: ct.get_insight_selectors(TrailName=trail["name"]),
        context="GetInsightSelectors after the rejected Put",
    )
    assert not_enabled_code == "InsightNotEnabledException", (
        f"expected the rejected Put to leave no selector persisted "
        f"(InsightNotEnabledException), got {not_enabled_code!r}"
    )
    expected_not_enabled = (
        f"Trail arn:aws:cloudtrail:{ctx.region}:{ctx.account}:trail/{trail['name']} does not have Insights "
        "enabled. Edit the trail settings to enable Insights, and then try the operation again."
    )
    assert not_enabled_message == expected_not_enabled, not_enabled_message

    # Positive control: a supported InsightType value succeeds.
    resp = ct.put_insight_selectors(
        TrailName=trail["name"], InsightSelectors=[{"InsightType": "ApiCallRateInsight"}]
    )
    persisted = resp["InsightSelectors"]
    assert len(persisted) == 1, f"expected exactly one persisted selector, got {persisted!r}"
    assert persisted[0]["InsightType"] == "ApiCallRateInsight", (
        f"expected ApiCallRateInsight, got {persisted[0]!r}"
    )
    confirm = ct.get_insight_selectors(TrailName=trail["name"])["InsightSelectors"]
    assert len(confirm) == 1, f"expected exactly one selector on independent read, got {confirm!r}"
    assert confirm[0]["InsightType"] == "ApiCallRateInsight", (
        f"expected ApiCallRateInsight on independent read, got {confirm[0]!r}"
    )


def _error(fn, *, context: str) -> tuple[str, str]:
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected {context} to fail, but it SUCCEEDED and returned {result!r}")


def _create_trail(ctx) -> dict[str, Any]:
    """Create a minimal, real CloudTrail trail backed by a fresh S3 bucket
    with the standard CloudTrail bucket policy, registering cleanup."""
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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]})

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

    trail_name = ctx.unique_name("sim2real-ct-trail-")
    deadline = time.monotonic() + 30
    resp = None
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            resp = ct.create_trail(
                Name=trail_name, S3BucketName=bucket, IncludeGlobalServiceEvents=True
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
    ct.add_tags(ResourceId=resp["TrailARN"], TagsList=[
        {"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}])
    return {"name": trail_name, "arn": resp["TrailARN"], "bucket": bucket}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
