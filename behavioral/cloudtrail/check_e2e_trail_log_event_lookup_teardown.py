"""e2e-trail-log-event-lookup-teardown."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-trail-log-event-lookup-teardown"
GROUP = "e2e"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GetTrailStatus call on a logging trail surfaces in LookupEvents with its trail name;
    StopLogging then sets IsLogging false and DeleteTrail removes the trail entirely."""
    ct = ctx.client("cloudtrail")
    trail = _create_trail_with_bucket(ctx)

    ct.start_logging(Name=trail["name"])
    ct.put_event_selectors(
        TrailName=trail["name"],
        EventSelectors=[{"ReadWriteType": "All", "IncludeManagementEvents": True}],
    )

    marker_time = datetime.now(timezone.utc) - timedelta(seconds=5)
    ct.get_trail_status(Name=trail["name"])

    # Event History can take up to ~15 minutes to show a management event.
    found = _poll_until(
        lambda: _lookup_our_event(ct, trail["name"], marker_time),
        lambda ev: ev is not None,
        timeout_s=600.0,
        interval_s=20.0,
    )
    assert found is not None, (
        f"expected GetTrailStatus on trail {trail['name']!r} to surface via "
        "LookupEvents within the poll window, got no match"
    )
    event_payload = json.loads(found["CloudTrailEvent"])
    assert event_payload["eventName"] == "GetTrailStatus", (
        f"expected eventName 'GetTrailStatus', got {event_payload['eventName']!r}"
    )
    assert event_payload["requestParameters"]["name"] == trail["name"], (
        f"expected requestParameters.name {trail['name']!r}, "
        f"got {event_payload['requestParameters'].get('name')!r}"
    )

    ct.stop_logging(Name=trail["name"])
    is_logging = _poll_until(
        lambda: ct.get_trail_status(Name=trail["name"])["IsLogging"],
        lambda logging: logging is False,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert is_logging is False, (
        f"expected IsLogging False after StopLogging on trail {trail['name']!r}, "
        f"got {is_logging!r}"
    )

    ct.delete_trail(Name=trail["name"])
    remaining = ct.describe_trails(trailNameList=[trail["name"]])["trailList"]
    assert remaining == [], f"expected trail {trail['name']!r} gone from DescribeTrails, got {remaining!r}"
    _assert_trail_gone(ct, trail["name"], ctx.account, ctx.region)


def _create_trail_with_bucket(ctx):
    s3 = ctx.client("s3")
    ct = ctx.client("cloudtrail")
    region = ctx.region
    bucket = ctx.unique_name("sim2real-ct-e2e-b-").lower()[:63]
    # us-east-1 is the one region where S3 rejects an explicit LocationConstraint.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    trail_name = ctx.unique_name("sim2real-ct-e2e-t-")
    s3.put_bucket_policy(
        Bucket=bucket, Policy=_bucket_policy_json(bucket, account_id, region, trail_name)
    )
    resp = ct.create_trail(
        Name=trail_name,
        S3BucketName=bucket,
        TagsList=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_trail_if_exists(ctx, trail_name))
    return {"name": trail_name, "arn": resp["TrailARN"], "bucket": bucket}


def _delete_trail_if_exists(ctx, trail_name: str) -> None:
    ct = ctx.client("cloudtrail")
    try:
        ct.delete_trail(Name=trail_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise


def _bucket_policy_json(bucket: str, account_id: str, region: str, trail_name: str) -> str:
    trail_arn = f"arn:aws:cloudtrail:{region}:{account_id}:trail/{trail_name}"
    return json.dumps(
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


def _assert_trail_gone(ct, trail_name: str, account_id: str, region: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ct.get_trail_status(Name=trail_name)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "TrailNotFoundException", (
            f"expected TrailNotFoundException for GetTrailStatus on deleted trail "
            f"{trail_name!r}, got {code!r}"
        )
        message = exc.response["Error"].get("Message")
        assert message == (
            f"Unknown trail: arn:aws:cloudtrail:{region}:{account_id}:trail/{trail_name} "
            f"for the user: {account_id}"
        ), message
    else:
        raise AssertionError(
            f"GetTrailStatus succeeded on trail {trail_name!r} after DeleteTrail"
        )


def _lookup_our_event(ct, trail_name: str, marker_time):
    resp = ct.lookup_events(
        LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "GetTrailStatus"}],
        StartTime=marker_time,
    )
    for event in resp.get("Events", []):
        try:
            payload = json.loads(event["CloudTrailEvent"])
        except (ValueError, KeyError):
            continue
        if payload.get("requestParameters", {}).get("name") == trail_name:
            return event
    return None


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
