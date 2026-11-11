"""glue-crawler-state-change-event-delivered-to-target-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "glue-crawler-state-change-event-delivered-to-target-positive"
GROUP = "event-propagation"
SERVICES = ["athena", "glue", "s3"]

GLUE_SERVICE_ROLE_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A real Glue Crawler run that finishes Succeeded emits a "Glue Crawler State Change"
    event that EventBridge delivers, via a matching rule, to a Kinesis Data Firehose target
    that archives the raw event payload as an object in S3."""
    data_bucket = _create_bucket(ctx, "data")
    archive_bucket = _create_bucket(ctx, "archive")
    s3 = ctx.client("s3")
    s3.put_object(Bucket=data_bucket, Key="data/sample.csv", Body=b"id,name\n1,a\n2,b\n")

    glue_role_arn = _create_glue_role(ctx, data_bucket)
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real_glue_db_")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    crawler_name = ctx.unique_name("sim2real-crawler-")
    _create_crawler_with_retry(
        glue,
        Name=crawler_name,
        Role=glue_role_arn,
        DatabaseName=db_name,
        Targets={"S3Targets": [{"Path": f"s3://{data_bucket}/data/"}]},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=crawler_name))

    firehose_role_arn = _create_firehose_role(ctx, archive_bucket)
    firehose = ctx.client("firehose")
    stream_name = ctx.unique_name("sim2real-glue-evt-fh-")
    _create_delivery_stream_with_retry(
        firehose,
        DeliveryStreamName=stream_name,
        DeliveryStreamType="DirectPut",
        S3DestinationConfiguration={
            "RoleARN": firehose_role_arn,
            "BucketARN": f"arn:aws:s3:::{archive_bucket}",
            "Prefix": "glue-events/",
            "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))
    stream_arn = _wait_for_firehose_active(ctx, stream_name)

    events_role_arn = _create_events_to_firehose_role(ctx, stream_arn)

    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-glue-crawler-rule-")
    pattern = {
        "source": ["aws.glue"],
        "detail-type": ["Glue Crawler State Change"],
        "detail": {"crawlerName": [crawler_name], "state": ["Succeeded"]},
    }
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    events.put_targets(
        Rule=rule_name, Targets=[{"Id": "archive", "Arn": stream_arn, "RoleArn": events_role_arn}]
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["archive"]))

    _start_crawler_with_retry(ctx, crawler_name)
    _wait_for_crawler_state(ctx, crawler_name, {"READY"}, timeout_s=420)
    last_status = glue.get_crawler(Name=crawler_name)["Crawler"]["LastCrawl"]["Status"]
    assert last_status == "SUCCEEDED", f"expected crawler LastCrawl SUCCEEDED, got {last_status}"

    payload = _wait_for_archived_event(ctx, archive_bucket, "glue-events/", crawler_name, timeout_s=240)
    assert payload["source"] == "aws.glue", f"expected source aws.glue, got {payload['source']!r}"
    assert payload["detail-type"] == "Glue Crawler State Change", (
        f"expected detail-type 'Glue Crawler State Change', got {payload['detail-type']!r}"
    )
    assert payload["detail"]["crawlerName"] == crawler_name, (
        f"expected archived event for crawler {crawler_name!r}, got {payload['detail']['crawlerName']!r}"
    )
    assert payload["detail"]["state"] == "Succeeded", (
        f"expected archived event state Succeeded, got {payload['detail']['state']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_bucket(ctx, suffix: str) -> str:
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name(f"sim2real-glue-{suffix}-")
    kwargs: dict[str, Any] = {"Bucket": bucket_name}
    # us-east-1 literal: not a region pin — S3's CreateBucket rejects an explicit
    # LocationConstraint for the default region, so it's the one value that must
    # be omitted rather than passed through from ctx.region.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket_name))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket_name


def _empty_and_delete_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [
                {"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket_name)


def _create_glue_role(ctx, bucket_name: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=GLUE_SERVICE_ROLE_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=GLUE_SERVICE_ROLE_POLICY_ARN))
    s3_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(s3_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"))
    return role_arn


def _create_firehose_role(ctx, archive_bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:GetBucketLocation",
                    "s3:ListBucket",
                    "s3:AbortMultipartUpload",
                ],
                "Resource": [f"arn:aws:s3:::{archive_bucket}", f"arn:aws:s3:::{archive_bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-write", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-write"))
    return role_arn


def _create_events_to_firehose_role(ctx, stream_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-evt-fh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "firehose:PutRecord", "Resource": stream_arn}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="firehose-put", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="firehose-put"))
    # No sleep here: EventBridge does not validate that a target's RoleArn is
    # assumable at PutTargets time (that only surfaces later, as a failed
    # invocation). The role has ample time to propagate during the crawler
    # run and the bounded polls below.
    return role_arn


def _create_crawler_with_retry(glue, retries: int = 6, delay: float = 10.0, **kwargs) -> None:
    """A freshly created IAM role can take a short time to become assumable by
    Glue; CreateCrawler validates assumability synchronously, so retry through
    that documented eventual-consistency window instead of failing immediately."""
    for attempt in range(retries):
        try:
            glue.create_crawler(**kwargs)
            return
        except ClientError as exc:
            if "unable to assume" in str(exc).lower() and attempt < retries - 1:
                time.sleep(delay)
                continue
            raise


def _create_delivery_stream_with_retry(firehose, retries: int = 6, delay: float = 10.0, **kwargs) -> None:
    """A freshly created IAM role can take a short time to become assumable by
    Firehose; CreateDeliveryStream validates the role's trust policy
    synchronously, so retry through that eventual-consistency window instead
    of failing immediately."""
    for attempt in range(retries):
        try:
            firehose.create_delivery_stream(**kwargs)
            return
        except ClientError as exc:
            msg = str(exc).lower()
            if ("assum" in msg or "trust" in msg) and attempt < retries - 1:
                time.sleep(delay)
                continue
            raise


def _wait_for_firehose_active(ctx, stream_name: str, timeout_s: float = 120.0) -> str:
    firehose = ctx.client("firehose")
    desc = _poll_until(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"],
        lambda d: d["DeliveryStreamStatus"] == "ACTIVE",
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"delivery stream {stream_name} becoming ACTIVE",
    )
    return desc["DeliveryStreamARN"]


def _start_crawler_with_retry(ctx, crawler_name: str, timeout_s: float = 60.0) -> None:
    """Retry StartCrawler every 2 s to a deadline while its role or target settles."""
    glue = ctx.client("glue")
    deadline = time.monotonic() + timeout_s
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + left)
    while True:
        try:
            glue.start_crawler(Name=crawler_name)
            return
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _wait_for_crawler_state(ctx, crawler_name: str, terminal_states: set, timeout_s: float = 420.0) -> None:
    glue = ctx.client("glue")
    _poll_until(
        lambda: glue.get_crawler(Name=crawler_name)["Crawler"]["State"],
        lambda s: s in terminal_states,
        timeout_s=timeout_s,
        interval_s=10.0,
        description=f"crawler {crawler_name} reaching {terminal_states}",
    )


def _wait_for_archived_event(
    ctx, bucket: str, prefix: str, crawler_name: str, timeout_s: float = 240.0
) -> dict[str, Any]:
    s3 = ctx.client("s3")

    def probe():
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        for obj in resp.get("Contents", []):
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read().decode("utf-8", "ignore").strip()
            if not body:
                continue
            try:
                payload = json.loads(body)
            except ValueError:
                continue
            if payload.get("detail", {}).get("crawlerName") == crawler_name:
                return payload
        return None

    result = _poll_until(
        probe,
        lambda r: r is not None,
        timeout_s=timeout_s,
        interval_s=10.0,
        description="archived Glue Crawler event object in S3",
    )
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
