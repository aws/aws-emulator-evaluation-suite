"""put-get-insight-selectors-roundtrip."""

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


def _trail_arn(ctx, name):
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:cloudtrail:{ctx.region}:{account}:trail/{name}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0):
    """Retry probe() until predicate(value) holds; raise (never return stale) on timeout."""
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


CHECK = "put-get-insight-selectors-roundtrip"
GROUP = 'trail-config'
SERVICES = ['cloudtrail']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutInsightSelectors enables insights and GetInsightSelectors reflects the configured types."""
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-ct-trail-")
    _create_trail(ctx, ct, s3, name)

    put_resp = _call(
        lambda: ct.put_insight_selectors(
            TrailName=name,
            InsightSelectors=[{"InsightType": "ApiCallRateInsight"}],
        )
    )
    types = [s["InsightType"] for s in put_resp["InsightSelectors"]]
    assert "ApiCallRateInsight" in types, f"expected ApiCallRateInsight in put response, got {types}"

    # GetInsightSelectors reflecting a just-configured selector is eventually consistent on real AWS
    # -- an unguarded immediate read can observe the pre-put state.
    def _try_get_insight_selectors():
        try:
            return ct.get_insight_selectors(TrailName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InsightNotEnabledException":
                return None
            raise

    got = _poll_until(
        _try_get_insight_selectors,
        lambda r: r is not None and [s["InsightType"] for s in r["InsightSelectors"]] == ["ApiCallRateInsight"],
    )
    types = [s["InsightType"] for s in got["InsightSelectors"]]
    assert types == ["ApiCallRateInsight"], f"expected [ApiCallRateInsight], got {types}"
    expected_arn = _trail_arn(ctx, name)
    assert got["TrailARN"] == expected_arn, f"expected TrailARN {expected_arn}, got {got['TrailARN']}"

    # Enabling insights flips the trail's summary flag -- also eventually consistent.
    has_insights = _poll_until(
        lambda: ct.get_trail(Name=name)["Trail"]["HasInsightSelectors"],
        lambda v: v is True,
    )
    assert has_insights is True, f"expected HasInsightSelectors True, got {has_insights}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
