"""e2e-trail-logging-lookup-events-consequence."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-trail-logging-lookup-events-consequence"
GROUP = "e2e"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """LookupEvents surfaces the trail's own CreateTrail/PutEventSelectors/StartLogging calls, and
    after stop and delete the trail is gone from both GetTrailStatus and DescribeTrails.

    Reference: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html
    """
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region
    trail_name = ctx.unique_name("sim2real-e2e-trail-")
    bucket_name = ctx.unique_name("sim2real-e2e-trailbkt-").lower()
    trail_arn = f"arn:aws:cloudtrail:{region}:{account_id}:trail/{trail_name}"

    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket_name))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    bucket_policy = {
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
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(bucket_policy))

    ct.create_trail(
        Name=trail_name,
        S3BucketName=bucket_name,
        IsMultiRegionTrail=False,
        TagsList=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_trail_if_exists(ct, trail_name))

    ct.put_event_selectors(
        TrailName=trail_name,
        EventSelectors=[{"ReadWriteType": "All", "IncludeManagementEvents": True}],
    )
    ct.start_logging(Name=trail_name)
    ctx.on_cleanup(lambda: _stop_logging_if_exists(ct, trail_name))

    # Event history records CloudTrail's own management calls whether or not a trail is logging,
    # typically within minutes; poll with a bounded timeout so a genuine miss raises a readable
    # AssertionError.
    matched = _poll_until(
        lambda: ct.lookup_events(
            LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": trail_name}],
            MaxResults=50,
        )["Events"],
        lambda events: any(
            e["EventName"] in ("CreateTrail", "PutEventSelectors", "StartLogging") for e in events
        ),
        timeout_s=250,
        interval_s=20,
    )
    event_names = {e["EventName"] for e in matched}
    assert event_names & {"CreateTrail", "PutEventSelectors", "StartLogging"}, (
        f"expected LookupEvents(ResourceName={trail_name!r}) to surface one of "
        f"CreateTrail/PutEventSelectors/StartLogging, got event names {event_names!r}"
    )
    for event in matched:
        if event["EventName"] in ("CreateTrail", "PutEventSelectors", "StartLogging"):
            body = json.loads(event["CloudTrailEvent"])
            assert body["eventName"] == event["EventName"], (
                f"CloudTrailEvent body eventName {body['eventName']!r} disagrees with the "
                f"LookupEvents field {event['EventName']!r} for the same record"
            )

    ct.stop_logging(Name=trail_name)
    is_logging = ct.get_trail_status(Name=trail_name)["IsLogging"]
    assert is_logging is False, f"expected IsLogging=False after StopLogging, got {is_logging!r}"

    ct.delete_trail(Name=trail_name)
    try:
        status = ct.get_trail_status(Name=trail_name)
        raise AssertionError(
            f"expected TrailNotFoundException for deleted trail {trail_name}, got status {status!r}"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "TrailNotFoundException", (
            f"expected TrailNotFoundException after delete_trail, got {code!r}"
        )
        message = exc.response["Error"].get("Message")
        assert message == f"Unknown trail: {trail_arn} for the user: {account_id}", message
    remaining = ct.describe_trails(trailNameList=[trail_name]).get("trailList", [])
    assert not remaining, (
        f"expected trail {trail_name} gone from DescribeTrails after delete_trail, found {remaining!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition never met, last value: {value!r}")


def _stop_logging_if_exists(ct, trail_name):
    try:
        ct.stop_logging(Name=trail_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise


def _delete_trail_if_exists(ct, trail_name):
    try:
        ct.delete_trail(Name=trail_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise


def _delete_bucket(ctx, bucket_name):
    s3 = ctx.client("s3")
    try:
        resp = s3.list_object_versions(Bucket=bucket_name)
        objects = [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in resp.get("Versions", [])]
        objects += [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in resp.get("DeleteMarkers", [])]
        if objects:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
