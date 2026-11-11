"""get-insight-selectors-not-enabled-fails."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises.

    An unexpected success raises, so an over-permissive target fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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


CHECK = "get-insight-selectors-not-enabled-fails"
GROUP = 'error-semantics'
SERVICES = ['cloudtrail']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetInsightSelectors on a trail with no PutInsightSelectors call raises
    InsightNotEnabledException; an invalid InsightType is rejected by
    PutInsightSelectors, and the rejection must not half-enable insights."""
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-ct-trail-")
    trail_arn = _create_trail(ctx, ct, s3, name)["TrailARN"]
    not_enabled = (
        f"Trail {trail_arn} does not have Insights enabled. Edit the trail settings to enable "
        "Insights, and then try the operation again."
    )

    code, message = _error(lambda: ct.get_insight_selectors(TrailName=name))
    assert code == "InsightNotEnabledException", (code, message)
    assert message == not_enabled, message

    put_code, put_message = _error(
        lambda: ct.put_insight_selectors(
            TrailName=name, InsightSelectors=[{"InsightType": "NotARealInsight"}]
        )
    )
    assert put_code == "InvalidInsightSelectorsException", (put_code, put_message)
    assert put_message == (
        "The provided value is not a valid Insights type: NotARealInsight. Valid Insight types "
        "are: ApiCallRateInsight and ApiErrorRateInsight. Verify your input and then try again."
    ), put_message

    # The rejected Put must not have half-enabled Insights on the trail.
    code, message = _error(lambda: ct.get_insight_selectors(TrailName=name))
    assert code == "InsightNotEnabledException", (code, message)
    assert message == not_enabled, message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
