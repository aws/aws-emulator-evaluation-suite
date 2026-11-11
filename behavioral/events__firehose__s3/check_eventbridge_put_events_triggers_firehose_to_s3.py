"""eventbridge-put-events-triggers-firehose-to-s3."""
from __future__ import annotations

import json
import re
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-put-events-triggers-firehose-to-s3"
GROUP = "event-propagation"
SERVICES = ["events", "firehose", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A batched PutEvents call, routed through a matching EventBridge rule and its Firehose
    target, lands every event as a distinct object/record in the S3 destination bucket, using
    Firehose's default time-partitioned key layout."""
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
    # EventBridge does not retry a target invocation that fails with AccessDenied because
    # ev_role/fh_role are still propagating -- unlike a throttling error, that is a non-retryable
    # classification, so the very first attempt must land or the event is dropped for good. Resend
    # a throwaway event (not just re-read) until one round-trips through EventBridge -> Firehose ->
    # S3, which is a bounded, stated-reason stand-in for a blind sleep and proves the wiring is
    # actually hot before the batch under test is sent.
    _warm_up_delivery(ctx, bucket, events, source)

    markers = [ctx.unique_name(f"marker-{i}-") for i in range(3)]
    events.put_events(
        Entries=[
            {
                "Source": source,
                "DetailType": "sim2real.test.batch",
                "Detail": json.dumps({"marker": m, "index": i}),
            }
            for i, m in enumerate(markers)
        ]
    )

    records = _poll_for_records(
        ctx,
        bucket,
        lambda recs: {r.get("detail", {}).get("marker") for r in recs} >= set(markers),
        description="all batched events delivered to S3 via Firehose",
    )
    seen = {r["detail"]["marker"]: r for r in records if r.get("detail", {}).get("marker") in markers}
    assert set(seen.keys()) == set(markers), f"expected all of {markers}, saw {list(seen)}"
    for i, m in enumerate(markers):
        assert seen[m]["detail"]["index"] == i, (
            f"marker {m}: expected index {i}, got {seen[m]['detail']['index']}"
        )
        assert seen[m]["source"] == source, (
            f"marker {m}: expected source {source!r}, got {seen[m]['source']!r}"
        )

    # Firehose's default S3 key layout (no custom Prefix) is <prefix?>YYYY/MM/DD/HH/<stream>-...
    s3 = ctx.client("s3")
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket=bucket).get("Contents", [])]
    assert keys, "expected at least one delivered S3 object"
    assert any(re.match(r"^\d{4}/\d{2}/\d{2}/\d{2}/", k) for k in keys), (
        f"expected default YYYY/MM/DD/HH/ key prefix, got {keys}"
    )


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
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]}
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
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
            }
        ],
    }
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    # No unconditional sleep: freshly-created-role propagation to firehose.amazonaws.com is
    # absorbed by _create_delivery_stream's own bounded ClientError-retry loop below.
    return role_arn


def _create_delivery_stream(ctx, bucket_arn: str, role_arn: str, prefix: str | None = None) -> dict[str, str]:
    fh = ctx.client("firehose")
    name = ctx.unique_name("sim2real-fh-")
    s3_config: dict[str, Any] = {
        "RoleARN": role_arn,
        "BucketARN": bucket_arn,
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
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
                Tags=[{"Key": "sim2real", "Value": "true"}],
            )
            break
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(5.0)
    ctx.on_cleanup(lambda: fh.delete_delivery_stream(DeliveryStreamName=name))
    desc = _poll_until(
        lambda: fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"],
        lambda d: d["DeliveryStreamStatus"] == "ACTIVE",
        timeout_s=120.0,
        interval_s=3.0,
        description=f"delivery stream {name} ACTIVE",
    )
    return {"name": name, "arn": desc["DeliveryStreamARN"]}


def _create_events_role(
    ctx, stream_arns: list[str] | None = None, trusted_service: str = "events.amazonaws.com"
) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-evrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trusted_service}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
            RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy)
        )
        ctx.on_cleanup(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        )
    # No unconditional sleep: freshly-created-role propagation to events.amazonaws.com is
    # absorbed by _put_target's own bounded FailedEntryCount-retry loop below.
    return role_arn


def _create_rule(ctx, pattern: dict[str, Any]) -> str:
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-evfh-rule-")
    events.put_rule(
        Name=name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": "true"}],
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


def _warm_up_delivery(
    ctx, bucket: str, events, source: str, *, timeout_s: float = 180.0, attempt_window_s: float = 20.0
) -> None:
    deadline = time.monotonic() + timeout_s
    last_seen: list[dict] = []
    while time.monotonic() < deadline:
        marker = ctx.unique_name("warmup-")
        events.put_events(
            Entries=[
                {
                    "Source": source,
                    "DetailType": "sim2real.test.warmup",
                    "Detail": json.dumps({"marker": marker}),
                }
            ]
        )
        attempt_deadline = time.monotonic() + attempt_window_s
        while time.monotonic() < attempt_deadline:
            last_seen = _list_bucket_records(ctx, bucket)
            if any(r.get("detail", {}).get("marker") == marker for r in last_seen):
                return
            time.sleep(2.0)
    raise AssertionError(
        f"warmup event never delivered to S3 via Firehose within {timeout_s}s. Last result: {last_seen!r}"
    )


def _list_bucket_records(ctx, bucket: str) -> list[dict]:
    s3 = ctx.client("s3")
    records: list[dict] = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read().decode("utf-8")
            records.extend(_parse_concatenated_json(body))
    return records


def _poll_for_records(
    ctx, bucket: str, predicate, timeout_s: float = 240.0, interval_s: float = 15.0, description: str = "records in S3"
) -> list[dict]:
    return _poll_until(
        lambda: _list_bucket_records(ctx, bucket),
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
