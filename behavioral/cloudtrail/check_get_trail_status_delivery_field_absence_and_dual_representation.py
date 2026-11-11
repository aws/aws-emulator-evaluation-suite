"""get-trail-status-delivery-field-absence-and-dual-representation."""

from __future__ import annotations

import datetime
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


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
    # us-east-1 is S3's API-level default region: CreateBucket rejects an explicit
    # LocationConstraint of "us-east-1" with InvalidLocationConstraint, so the parameter
    # must be omitted there and only there — this is not a region pin on the resource.
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-behav", "Value": "true"}]})


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


def _purge_bucket_once(s3, bucket):
    """Delete every current object and every non-current version. Returns objects removed."""
    removed = 0
    for paginator_name, list_key, id_key in (
        ("list_objects_v2", "Contents", None),
        ("list_object_versions", "Versions", "VersionId"),
        ("list_object_versions", "DeleteMarkers", "VersionId"),
    ):
        try:
            paginator = s3.get_paginator(paginator_name)
        except Exception:
            continue
        try:
            for page in paginator.paginate(Bucket=bucket):
                entries = page.get(list_key, [])
                if not entries:
                    continue
                objects = []
                for entry in entries:
                    item = {"Key": entry["Key"]}
                    if id_key and entry.get(id_key):
                        item["VersionId"] = entry[id_key]
                    objects.append(item)
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
                removed += len(objects)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
            continue
    return removed


def _drain_and_delete_bucket(s3, bucket, *, attempts=6, delay_s=10.0):
    """Empty and delete a trail's log bucket, retrying because CloudTrail may still be writing:
    a log file landing between purge and delete makes DeleteBucket fail with BucketNotEmpty.
    Raises on a deadline miss so a leak is visible."""
    last = None
    for attempt in range(attempts):
        _purge_bucket_once(s3, bucket)
        try:
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("NoSuchBucket",):
                return
            last = exc
            if attempt < attempts - 1:
                time.sleep(delay_s)
    raise AssertionError(
        f"could not delete trail log bucket {bucket} after {attempts} attempts; "
        f"a billable S3 bucket has been leaked. Last error: {last}"
    )


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


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate() holds, raising on deadline miss."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last={last!r}")


def _parse_iso8601(value):
    """Parse CloudTrail's deprecated string-typed timestamp fields to an aware datetime."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed


CHECK = "get-trail-status-delivery-field-absence-and-dual-representation"
GROUP = 'trail-lifecycle'
SERVICES = ['cloudtrail']

# GetTrailStatus's history members, split by how AWS represents "no value yet": the Date-typed and
# error-string members are OMITTED; the six deprecated String twins are present as "".
_OMITTED_UNTIL_SET = (
    "LatestDeliveryError",
    "LatestNotificationError",
    "LatestDeliveryTime",
    "LatestNotificationTime",
    "StartLoggingTime",
    "StopLoggingTime",
    "LatestCloudWatchLogsDeliveryError",
    "LatestCloudWatchLogsDeliveryTime",
    "LatestDigestDeliveryTime",
    "LatestDigestDeliveryError",
)
_EMPTY_STRING_UNTIL_SET = (
    "LatestDeliveryAttemptTime",
    "LatestNotificationAttemptTime",
    "LatestNotificationAttemptSucceeded",
    "LatestDeliveryAttemptSucceeded",
    "TimeLoggingStarted",
    "TimeLoggingStopped",
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A never-logged trail's GetTrailStatus omits the Date-typed/error members but returns the six
    deprecated String twins as "", and after start/stop logging each String twin denotes the same
    instant as its Date-typed member. Log delivery itself is not asserted (it can take minutes).

    Reference: https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrailStatus.html
    """
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-behav-ct-bkt-").lower()
    _create_trail_bucket(s3, bucket, ctx.region, account)
    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, bucket))

    name = ctx.unique_name("sim2real-behav-ct-trail-")
    created = _call(lambda: ct.create_trail(Name=name, S3BucketName=bucket))
    ctx.on_cleanup(lambda: _delete_trail(ct, name))
    minted_arn = created["TrailARN"]
    assert minted_arn.endswith(f":trail/{name}"), minted_arn
    _call(lambda: ct.add_tags(ResourceId=minted_arn, TagsList=[{"Key": "team", "Value": "sim2real"}]))

    # Part 1: a trail that has never logged reports its history surface in TWO different
    # ways, and which member gets which representation is fixed.
    status = _trail_status(ct, name)
    assert status["IsLogging"] is False, status["IsLogging"]
    for field in _OMITTED_UNTIL_SET:
        assert field not in status, (
            f"GetTrailStatus returned {field}={status[field]!r} on a trail that has never "
            f"logged; this member must be OMITTED, not empty/null/zero"
        )
    for field in _EMPTY_STRING_UNTIL_SET:
        assert field in status, (
            f"GetTrailStatus omitted the deprecated String member {field} on a trail that "
            f"has never logged; real AWS always emits it, as '' when it has no value. "
            f"Omitting it breaks the older SDK consumers it exists for. Got: {sorted(status)}"
        )
        assert status[field] == "", (
            f"GetTrailStatus returned {field}={status[field]!r} on a trail that has never "
            f"logged; the deprecated String members carry exactly '' until they are set"
        )

    # Part 2: drive one logging window and compare each timestamp with its String twin.
    # Re-assert the minted ARN immediately before the mutating call.
    pre_start_arn = _call(lambda: ct.get_trail(Name=name))["Trail"]["TrailARN"]
    assert pre_start_arn == minted_arn, (pre_start_arn, minted_arn)
    _call(lambda: ct.start_logging(Name=name))
    started = _poll_until(
        lambda: _trail_status(ct, name),
        lambda s: s["IsLogging"] is True and "StartLoggingTime" in s,
        timeout_s=90,
        interval_s=3,
        description="trail reports IsLogging=True with a StartLoggingTime",
    )
    assert started.get("TimeLoggingStarted"), (
        "StartLoggingTime is set but its deprecated String twin TimeLoggingStarted is "
        f"still absent or empty: {started.get('TimeLoggingStarted')!r} in {sorted(started)}"
    )
    assert isinstance(started["TimeLoggingStarted"], str), (
        f"TimeLoggingStarted is {type(started['TimeLoggingStarted']).__name__}, not str"
    )
    delta = abs(
        (_parse_iso8601(started["TimeLoggingStarted"]) - started["StartLoggingTime"]).total_seconds()
    )
    # The String twin is truncated to whole seconds, hence the tolerance.
    assert delta < 2.0, (
        f"TimeLoggingStarted ({started['TimeLoggingStarted']}) and StartLoggingTime "
        f"({started['StartLoggingTime']}) differ by {delta}s"
    )
    # The empty-string convention is per-member and live, not just an initial snapshot: the
    # trail has not been stopped yet, so TimeLoggingStopped is still present and still "".
    assert started.get("TimeLoggingStopped") == "", (
        f"TimeLoggingStopped must still be '' before StopLogging, got "
        f"{started.get('TimeLoggingStopped')!r}"
    )
    # Nothing has failed, so the error members stay omitted; and if any IS present it must
    # be a non-empty string, never "" standing in for "no error".
    for field in ("LatestDeliveryError", "LatestNotificationError",
                  "LatestCloudWatchLogsDeliveryError", "LatestDigestDeliveryError"):
        if field in started:
            assert started[field], f"{field} present but empty: {started[field]!r}"

    pre_stop_arn = _call(lambda: ct.get_trail(Name=name))["Trail"]["TrailARN"]
    assert pre_stop_arn == minted_arn, (pre_stop_arn, minted_arn)
    _call(lambda: ct.stop_logging(Name=name))
    stopped = _poll_until(
        lambda: _trail_status(ct, name),
        lambda s: s["IsLogging"] is False and "StopLoggingTime" in s,
        timeout_s=90,
        interval_s=3,
        description="trail reports IsLogging=False with a StopLoggingTime",
    )
    assert stopped.get("TimeLoggingStopped"), (
        "StopLoggingTime is set but its deprecated String twin TimeLoggingStopped is "
        f"still absent or empty: {stopped.get('TimeLoggingStopped')!r} in {sorted(stopped)}"
    )
    assert isinstance(stopped["TimeLoggingStopped"], str), (
        f"TimeLoggingStopped is {type(stopped['TimeLoggingStopped']).__name__}, not str"
    )
    delta = abs(
        (_parse_iso8601(stopped["TimeLoggingStopped"]) - stopped["StopLoggingTime"]).total_seconds()
    )
    assert delta < 2.0, (
        f"TimeLoggingStopped ({stopped['TimeLoggingStopped']}) and StopLoggingTime "
        f"({stopped['StopLoggingTime']}) differ by {delta}s"
    )

    # The start markers survive the stop, in BOTH representations, and stay consistent.
    assert stopped["StartLoggingTime"] == started["StartLoggingTime"], (
        stopped["StartLoggingTime"],
        started["StartLoggingTime"],
    )
    assert stopped["TimeLoggingStarted"] == started["TimeLoggingStarted"], (
        stopped["TimeLoggingStarted"],
        started["TimeLoggingStarted"],
    )
    assert stopped["StopLoggingTime"] >= stopped["StartLoggingTime"], (
        stopped["StopLoggingTime"],
        stopped["StartLoggingTime"],
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
