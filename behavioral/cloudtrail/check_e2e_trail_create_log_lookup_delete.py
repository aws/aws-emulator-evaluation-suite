"""e2e-trail-create-log-lookup-delete."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-trail-create-log-lookup-delete"
GROUP = "e2e"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Full lifecycle: create a trail, start logging, generate activity, observe
    it via LookupEvents, stop logging, delete the trail, and confirm it is gone
    from both DescribeTrails and GetTrailStatus."""
    sts = ctx.client("sts")
    s3 = ctx.client("s3")
    ct = ctx.client("cloudtrail")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    bucket_name = ctx.unique_name("sim2real-ct-e2e-bucket-").lower()
    trail_name = ctx.unique_name("sim2real-ct-e2e-trail-")
    trail_arn = f"arn:aws:cloudtrail:{region}:{account_id}:trail/{trail_name}"

    if region == "us-east-1":
        # us-east-1 is the one region where S3 rejects an explicit LocationConstraint.
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region}
        )

    def _cleanup_bucket() -> None:
        try:
            paginator = s3.get_paginator("list_objects_v2")
            keys = [
                {"Key": o["Key"]}
                for page in paginator.paginate(Bucket=bucket_name)
                for o in page.get("Contents", [])
            ]
            for i in range(0, len(keys), 1000):
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": keys[i : i + 1000]}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
        s3.delete_bucket(Bucket=bucket_name)

    ctx.on_cleanup(_cleanup_bucket)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket_name}",
                "Condition": {"StringEquals": {"aws:SourceArn": trail_arn}},
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceArn": trail_arn,
                    }
                },
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))

    ct.create_trail(
        Name=trail_name,
        S3BucketName=bucket_name,
        IncludeGlobalServiceEvents=True,
        IsMultiRegionTrail=False,
    )

    def _cleanup_trail() -> None:
        try:
            ct.delete_trail(Name=trail_name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TrailNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_trail)

    ct.start_logging(Name=trail_name)
    status = _poll_until(
        lambda: ct.get_trail_status(Name=trail_name),
        lambda s: s.get("IsLogging") is True,
        timeout_s=60,
        interval_s=3,
    )
    assert status["IsLogging"] is True, f"expected IsLogging=True after StartLogging, got {status!r}"

    # Generate a distinctive, timestamped bit of activity on the trail's own
    # control plane and confirm it surfaces through LookupEvents.
    marker_time = datetime.now(timezone.utc) - timedelta(seconds=5)
    ct.list_tags(ResourceIdList=[trail_arn])

    events = _poll_until(
        lambda: ct.lookup_events(
            LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "ListTags"}],
            StartTime=marker_time,
        ).get("Events", []),
        lambda evs: any(trail_arn in e.get("CloudTrailEvent", "") for e in evs),
        timeout_s=900,
        interval_s=20,
    )
    assert any(
        e["EventName"] == "ListTags" and trail_arn in e.get("CloudTrailEvent", "")
        for e in events
    ), "expected LookupEvents to surface our ListTags call against this trail"

    ct.stop_logging(Name=trail_name)
    stopped = _poll_until(
        lambda: ct.get_trail_status(Name=trail_name),
        lambda s: s.get("IsLogging") is False,
        timeout_s=60,
        interval_s=3,
    )
    assert stopped["IsLogging"] is False, f"expected IsLogging=False after StopLogging, got {stopped!r}"

    ct.delete_trail(Name=trail_name)

    code, status, message = _error(lambda: ct.get_trail_status(Name=trail_name))
    assert code == "TrailNotFoundException", f"expected TrailNotFoundException after DeleteTrail, got {code!r}"
    assert status == 400, f"expected HTTP 400 from GetTrailStatus on the deleted trail, got {status!r}"
    expected_message = f"Unknown trail: {trail_arn} for the user: {ctx.account}"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    remaining = ct.describe_trails(trailNameList=[]).get("trailList", [])
    assert not any(t["Name"] == trail_name for t in remaining), (
        f"deleted trail {trail_name!r} still present in DescribeTrails: {remaining!r}"
    )

    # The dead trail is unusable, not just unlisted.
    code2, status2, message2 = _error(lambda: ct.start_logging(Name=trail_name))
    assert code2 == "TrailNotFoundException", f"expected TrailNotFoundException from StartLogging, got {code2!r}"
    assert status2 == 400, f"expected HTTP 400 from StartLogging on the deleted trail, got {status2!r}"
    expected_message = f"Unknown trail: {trail_arn} for the user: {ctx.account}"
    assert message2 == expected_message, f"expected the message {expected_message!r}, got {message2!r}"


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn) -> tuple[str | None, int | None, str]:
    """(Error.Code, HTTP status, Error.Message) of the ClientError fn() raises; an unexpected
    success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
