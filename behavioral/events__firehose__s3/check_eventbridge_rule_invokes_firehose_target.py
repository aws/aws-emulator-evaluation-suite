"""eventbridge-rule-invokes-firehose-target."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-rule-invokes-firehose-target"
GROUP = "event-propagation"
SERVICES = ["events", "firehose", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """An EventBridge rule with a Firehose delivery-stream target delivers a matching
    custom event's full envelope through Firehose into the wired S3 destination bucket."""
    bucket = _create_bucket(ctx)
    fh_role_arn = _create_firehose_role(ctx, _bucket_arn(bucket))
    stream = _create_delivery_stream(ctx, _bucket_arn(bucket), fh_role_arn)
    ev_role_arn = _create_events_role(ctx, stream_arns=[stream["arn"]])

    source = ctx.unique_name("sim2real-evfh-src-")
    rule_name = _create_rule(ctx, {"source": [source]})
    _put_target(
        ctx,
        rule_name,
        {"Id": "firehose-target", "Arn": stream["arn"], "RoleArn": ev_role_arn},
        "firehose-target",
    )

    events = ctx.client("events")
    # Neither role's cross-service IAM propagation can be probed: re-publish a fresh marker every
    # 10 s until one of them lands in S3, polling every 2 s.
    published: list[str] = []
    matched: list[dict] = []
    deadline = time.monotonic() + 240.0
    if ctx.time_left() is not None:
        deadline = min(deadline, time.monotonic() + ctx.time_left())
    next_put = 0.0
    try:
        while not matched:
            if time.monotonic() >= deadline:
                raise AssertionError(f"none of {len(published)} published events reached S3 via Firehose")
            if time.monotonic() >= next_put:
                marker = ctx.unique_name("marker-")
                events.put_events(
                    Entries=[
                        {
                            "Source": source,
                            "DetailType": "sim2real.test.event",
                            "Detail": json.dumps({"marker": marker, "value": 42}),
                        }
                    ]
                )
                published.append(marker)
                next_put = time.monotonic() + 10.0
            time.sleep(2)
            records = _list_bucket_records(ctx, bucket)
            delivered = next(
                (r["detail"]["marker"] for r in records if r.get("detail", {}).get("marker") in published), None
            )
            matched = [r for r in records if delivered and r.get("detail", {}).get("marker") == delivered]
    except AssertionError:
        logs = ctx.client("logs")
        events_seen = logs.get_log_events(
            logGroupName=f"/aws/kinesisfirehose/{stream['name']}",
            logStreamName="S3Delivery",
        )["events"]
        raise AssertionError(
            f"DIAGNOSTIC firehose delivery log events: {[e['message'] for e in events_seen]}"
        )
    assert len(matched) == 1, f"expected exactly one matching record, got {matched}"
    assert matched[0]["source"] == source
    assert matched[0]["detail-type"] == "sim2real.test.event"
    assert matched[0]["detail"]["value"] == 42


# ===== helpers =====


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-evfh-")
    if ctx.region == "us-east-1":
        # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1 itself.
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )

    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if objs:
            s3.delete_objects(
                Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            )
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _bucket_arn(name: str) -> str:
    return f"arn:aws:s3:::{name}"


def _create_firehose_role(ctx, bucket_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fhrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "firehose.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
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
                    "s3:GetBucketLocation",
                    "s3:ListBucket",
                    "s3:AbortMultipartUpload",
                    "s3:GetObject",
                ],
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["logs:PutLogEvents", "logs:CreateLogStream"],
                "Resource": "arn:aws:logs:*:*:log-group:/aws/kinesisfirehose/*:*",
            },
        ],
    }
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy)
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return role_arn


def _create_delivery_stream(
    ctx, bucket_arn: str, role_arn: str, prefix: str | None = None
) -> dict[str, str]:
    fh = ctx.client("firehose")
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-fh-")
    log_group = f"/aws/kinesisfirehose/{name}"
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    logs.create_log_stream(logGroupName=log_group, logStreamName="S3Delivery")
    s3_config: dict[str, Any] = {
        "RoleARN": role_arn,
        "BucketARN": bucket_arn,
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        "CloudWatchLoggingOptions": {
            "Enabled": True,
            "LogGroupName": log_group,
            "LogStreamName": "S3Delivery",
        },
    }
    if prefix:
        s3_config["Prefix"] = prefix
    deadline = time.monotonic() + 60.0
    while True:
        try:
            fh.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                S3DestinationConfiguration=s3_config,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            break
        except ClientError:
            # Retries absorb IAM role propagation delay for fh_role_arn (bounded, 60s).
            if time.monotonic() >= deadline:
                raise
            time.sleep(5.0)
    ctx.on_cleanup(lambda: fh.delete_delivery_stream(DeliveryStreamName=name))
    desc = _poll_until(
        lambda: fh.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ],
        lambda d: d["DeliveryStreamStatus"] == "ACTIVE",
        timeout_s=120.0,
        interval_s=3.0,
        description=f"delivery stream {name} ACTIVE",
    )
    return {"name": name, "arn": desc["DeliveryStreamARN"]}


def _create_events_role(
    ctx,
    stream_arns: list[str] | None = None,
    trusted_service: str = "events.amazonaws.com",
) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-evrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trusted_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if stream_arns:
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                    "Resource": stream_arns,
                }
            ],
        }
        policy_name = f"{role_name}-policy"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy),
        )
        ctx.on_cleanup(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        )
    return role_arn


def _create_rule(ctx, pattern: dict[str, Any]) -> str:
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-evfh-rule-")
    events.put_rule(
        Name=name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=name))
    return name


def _put_target(ctx, rule_name: str, target: dict[str, Any], target_id: str) -> None:
    events = ctx.client("events")
    deadline = time.monotonic() + 60.0
    while True:
        resp = events.put_targets(Rule=rule_name, Targets=[target])
        if resp.get("FailedEntryCount", 0) == 0:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"put_targets failed: {resp}")
        time.sleep(5.0)
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))


def _parse_concatenated_json(text: str) -> list[dict]:
    decoder = json.JSONDecoder()
    idx = 0
    n = len(text)
    out: list[dict] = []
    while idx < n:
        while idx < n and text[idx] in " \t\r\n":
            idx += 1
        if idx >= n:
            break
        obj, end = decoder.raw_decode(text, idx)
        out.append(obj)
        idx = end
    return out


def _list_bucket_records(ctx, bucket: str) -> list[dict]:
    s3 = ctx.client("s3")
    records: list[dict] = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            body = (
                s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"]
                .read()
                .decode("utf-8")
            )
            records.extend(_parse_concatenated_json(body))
    return records


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
