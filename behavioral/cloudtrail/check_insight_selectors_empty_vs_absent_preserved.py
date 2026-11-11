"""insight-selectors-empty-vs-absent-preserved."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "insight-selectors-empty-vs-absent-preserved"
GROUP = "representation"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetInsightSelectors raises InsightNotEnabledException on a never-configured trail, reflects
    one configured selector, and raises the same error again after PutInsightSelectors([]),
    which disables Insights; empty and absent selectors are reported identically."""
    ct = ctx.client("cloudtrail")
    trail = _create_trail_with_bucket(ctx)

    not_enabled = (
        f"Trail {trail['arn']} does not have Insights enabled. Edit the trail settings to enable "
        "Insights, and then try the operation again."
    )
    never_configured_code, never_configured_message = _error(
        lambda: ct.get_insight_selectors(TrailName=trail["name"])
    )
    assert never_configured_code == "InsightNotEnabledException", never_configured_code
    assert never_configured_message == not_enabled, never_configured_message

    ct.put_insight_selectors(
        TrailName=trail["name"], InsightSelectors=[{"InsightType": "ApiCallRateInsight"}]
    )
    configured = _poll_until(
        lambda: _try_get_insight_selectors(ct, trail["name"]),
        lambda r: r is not None,
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert len(configured["InsightSelectors"]) == 1
    assert configured["InsightSelectors"][0]["InsightType"] == "ApiCallRateInsight"

    ct.put_insight_selectors(TrailName=trail["name"], InsightSelectors=[])
    _poll_until(
        lambda: _try_get_insight_selectors(ct, trail["name"]),
        lambda r: r is None,
        timeout_s=60.0,
        interval_s=5.0,
    )
    cleared_code, cleared_message = _error(lambda: ct.get_insight_selectors(TrailName=trail["name"]))
    assert cleared_code == "InsightNotEnabledException", cleared_code
    assert cleared_message == not_enabled, cleared_message


def _try_get_insight_selectors(ct, trail_name: str):
    from botocore.exceptions import ClientError

    try:
        return ct.get_insight_selectors(TrailName=trail_name)
    except ClientError:
        return None


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    import time

    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    if predicate(value):
        return value
    raise AssertionError(f"condition never satisfied within {timeout_s}s (last={value!r})")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_trail_with_bucket(ctx):
    import json

    s3 = ctx.client("s3")
    ct = ctx.client("cloudtrail")
    region = ctx.region
    bucket = ctx.unique_name("sim2real-ct-ins-b-").lower()[:63]
    # us-east-1 is S3's API default region and rejects an explicit LocationConstraint.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    trail_name = ctx.unique_name("sim2real-ct-ins-t-")
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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]})
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
