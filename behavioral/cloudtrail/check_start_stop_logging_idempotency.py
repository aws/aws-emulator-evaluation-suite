"""start-stop-logging-idempotency."""

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


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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


def _create_trail_bucket(s3, bucket, region, account_id, check_name):
    """Create an S3 bucket with the policy CloudTrail needs to deliver logs."""
    _create_bucket_only(s3, bucket, region)
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": check_name}]}
    )
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


def _trail_status(ct, name):
    return _call(lambda: ct.get_trail_status(Name=name))


def _create_trail(ctx, ct, s3, name, **kwargs):
    """Create a trail (provisioning a policy-ready bucket unless S3BucketName is
    given) and register best-effort teardown of the trail and any bucket made."""
    bucket = kwargs.pop("S3BucketName", None)
    if not bucket:
        bucket = ctx.unique_name("sim2real-behav-ct-bkt-").lower()
        account = ctx.client("sts").get_caller_identity()["Account"]
        _create_trail_bucket(s3, bucket, ctx.region, account, CHECK)
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    params = {"Name": name, "S3BucketName": bucket}
    params.setdefault("TagsList", [{"Key": "sim2real", "Value": CHECK}])
    params.update(kwargs)
    resp = _call(lambda: ct.create_trail(**params))
    ctx.on_cleanup(lambda: _delete_trail(ct, name))
    return resp


CHECK = "start-stop-logging-idempotency"
GROUP = 'trail-lifecycle'
SERVICES = ['cloudtrail']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopLogging on a non-logging trail and StartLogging on a logging trail are idempotent no-ops."""
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-ct-trail-")
    _create_trail(ctx, ct, s3, name)

    initial = _trail_status(ct, name)
    assert initial["IsLogging"] is False, f"expected a freshly created trail to report IsLogging=False, got {initial!r}"

    # StopLogging against an already-stopped trail must succeed, not error.
    _call(lambda: ct.stop_logging(Name=name))
    status = _trail_status(ct, name)
    assert status["IsLogging"] is False, f"expected IsLogging=False after StopLogging on a non-logging trail, got {status!r}"
    # Never having logged, the trail has no StartLoggingTime marker.
    assert "StartLoggingTime" not in status, f"expected no StartLoggingTime on a trail that never logged, got {status.get('StartLoggingTime')!r}"

    _call(lambda: ct.start_logging(Name=name))
    _poll_until(
        lambda: _trail_status(ct, name),
        lambda s: s["IsLogging"] is True,
        timeout_s=60,
        interval_s=3,
        description="trail reports IsLogging=True",
    )

    # StartLogging against an already-logging trail must also succeed.
    _call(lambda: ct.start_logging(Name=name))
    relogged = _trail_status(ct, name)
    assert relogged["IsLogging"] is True, f"expected IsLogging=True after a redundant StartLogging on an already-logging trail, got {relogged!r}"

    _call(lambda: ct.stop_logging(Name=name))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
