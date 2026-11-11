"""mutating-ops-unknown-trail-fail."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """(Error.Code, Error.Message) for the ClientError fn() raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _create_bucket_only(s3, bucket, region):
    kwargs = {"Bucket": bucket}
    # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1.
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise


def _create_trail_bucket(s3, bucket, region, account_id, check):
    """Create an S3 bucket with the policy CloudTrail needs to deliver logs."""
    _create_bucket_only(s3, bucket, region)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": check}]})
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


def _create_trail_bucket_tracked(ctx, s3, bucket, account_id):
    _create_trail_bucket(s3, bucket, ctx.region, account_id, CHECK)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    return bucket


def _create_trail_with_retry(ct, timeout: float = 60.0, interval: float = 3.0, **kwargs):
    """Retry CreateTrail while the just-written S3 bucket policy is still propagating
    (eventually consistent), which surfaces as InsufficientS3BucketPolicyException."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            return ct.create_trail(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InsufficientS3BucketPolicyException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval)


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0, reason=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{reason}: condition not met within {timeout_s}s, last={last}")


def _delete_trail(ct, name):
    try:
        ct.stop_logging(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise
    try:
        ct.delete_trail(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise


CHECK = "mutating-ops-unknown-trail-fail"
GROUP = 'error-semantics'
SERVICES = ['cloudtrail']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateTrail/StartLogging/StopLogging/PutEventSelectors on a missing trail raise the exact
    TrailNotFoundException and never create it; the same four calls succeed on a real trail first
    so the rejections cannot be a blanket denial."""
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus = ctx.unique_name("sim2real-behav-ct-nonexistent-")
    bucket = _create_trail_bucket_tracked(ctx, s3, ctx.unique_name("sim2real-behav-ct-bkt-").lower(), account_id)

    real_name = ctx.unique_name("sim2real-behav-ct-real-")
    _create_trail_with_retry(ct, Name=real_name, S3BucketName=bucket, TagsList=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_trail(ct, real_name))

    update_resp = ct.update_trail(Name=real_name, S3KeyPrefix="orig-prefix")
    assert update_resp["Name"] == real_name, f"expected UpdateTrail to echo {real_name!r}, got {update_resp.get('Name')!r}"

    assert ct.get_trail_status(Name=real_name)["IsLogging"] is False, "expected a fresh trail to start with IsLogging False"
    ct.start_logging(Name=real_name)
    status = _poll_until(
        lambda: ct.get_trail_status(Name=real_name),
        lambda s: s["IsLogging"] is True,
        reason="StartLogging on the real trail never flipped IsLogging to True",
    )
    assert status["IsLogging"] is True, f"expected IsLogging True after StartLogging, got {status['IsLogging']}"

    ct.stop_logging(Name=real_name)
    status = _poll_until(
        lambda: ct.get_trail_status(Name=real_name),
        lambda s: s["IsLogging"] is False,
        reason="StopLogging on the real trail never flipped IsLogging to False",
    )
    assert status["IsLogging"] is False, f"expected IsLogging False after StopLogging, got {status['IsLogging']}"

    selectors = [{"ReadWriteType": "All", "IncludeManagementEvents": True}]
    put_resp = ct.put_event_selectors(TrailName=real_name, EventSelectors=selectors)
    assert put_resp["EventSelectors"][0]["ReadWriteType"] == "All", (
        f"expected PutEventSelectors to persist ReadWriteType=All, got {put_resp['EventSelectors']}"
    )

    unknown_trail_message = (
        f"Unknown trail: arn:aws:cloudtrail:{ctx.region}:{account_id}:trail/{bogus} "
        f"for the user: {account_id}"
    )
    code, message = _error(lambda: ct.update_trail(Name=bogus, S3BucketName=bucket))
    assert code == "TrailNotFoundException", f"UpdateTrail(unknown trail): expected TrailNotFoundException, got {code}"
    assert message == unknown_trail_message, message

    code, message = _error(lambda: ct.start_logging(Name=bogus))
    assert code == "TrailNotFoundException", f"StartLogging(unknown trail): expected TrailNotFoundException, got {code}"
    assert message == unknown_trail_message, message

    code, message = _error(lambda: ct.stop_logging(Name=bogus))
    assert code == "TrailNotFoundException", f"StopLogging(unknown trail): expected TrailNotFoundException, got {code}"
    assert message == unknown_trail_message, message

    code, message = _error(
        lambda: ct.put_event_selectors(
            TrailName=bogus,
            EventSelectors=[
                {"ReadWriteType": "All", "IncludeManagementEvents": True}
            ],
        )
    )
    assert code == "TrailNotFoundException", f"PutEventSelectors(unknown trail): expected TrailNotFoundException, got {code}"
    assert message == unknown_trail_message, message

    trail_names = [t["Name"] for t in ct.list_trails().get("Trails", [])]
    assert bogus not in trail_names, f"expected {bogus!r} absent from ListTrails after four rejected mutations, found it in {trail_names}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
