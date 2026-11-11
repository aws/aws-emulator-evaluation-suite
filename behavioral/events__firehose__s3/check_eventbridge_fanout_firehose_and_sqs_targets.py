"""eventbridge-fanout-firehose-and-sqs-targets."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-fanout-firehose-and-sqs-targets"
GROUP = "event-propagation"
SERVICES = ["events", "firehose", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A single rule with two independent targets (a Firehose delivery stream and an SQS
    queue) fans a matching event out to BOTH: the record lands in the S3 destination via
    Firehose, and the same event envelope is delivered as an SQS message."""
    bucket = _create_bucket(ctx)
    fh_role_arn = _create_firehose_role(ctx, _bucket_arn(bucket))
    stream = _create_delivery_stream(ctx, _bucket_arn(bucket), fh_role_arn)
    ev_role_arn = _create_events_role(ctx, stream_arns=[stream["arn"]])

    source = ctx.unique_name("sim2real-evfh-src-")
    rule_name = _create_rule(ctx, {"source": [source]})
    rule_arn = ctx.client("events").describe_rule(Name=rule_name)["Arn"]
    queue = _create_queue_for_rule(ctx, rule_arn)

    _put_targets(
        ctx,
        rule_name,
        [
            {"Id": "firehose-target", "Arn": stream["arn"], "RoleArn": ev_role_arn},
            {"Id": "sqs-target", "Arn": queue["arn"]},
        ],
    )

    events = ctx.client("events")
    marker, matched = _deliver_until_firehose_receives(ctx, events, source, bucket)
    assert len(matched) == 1, f"expected exactly one record in S3, got {matched}"

    sqs = ctx.client("sqs")
    messages = _poll_until(
        lambda: sqs.receive_message(QueueUrl=queue["url"], MaxNumberOfMessages=10, WaitTimeSeconds=5).get(
            "Messages", []
        ),
        lambda msgs: any(marker in m["Body"] for m in msgs),
        timeout_s=90.0,
        interval_s=5.0,
        description="event delivered to the SQS target",
    )
    sqs_matched = [m for m in messages if marker in m["Body"]]
    assert len(sqs_matched) == 1, f"expected exactly one SQS message, got {sqs_matched}"
    body = json.loads(sqs_matched[0]["Body"])
    assert body["detail"]["marker"] == marker, (
        f"expected SQS envelope detail.marker {marker!r}, got {body['detail'].get('marker')!r}"
    )
    assert body["source"] == source, f"expected SQS envelope source {source!r}, got {body['source']!r}"


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
        # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1 itself
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
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
    # the role above was just created; retry on ClientError to tolerate IAM's
    # eventual-consistency window before Firehose can validate/assume it
    deadline = time.monotonic() + 60.0
    while True:
        try:
            fh.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                S3DestinationConfiguration=s3_config,
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
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
    return role_arn


def _create_rule(ctx, pattern: dict[str, Any]) -> str:
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-evfh-rule-")
    events.put_rule(Name=name, EventPattern=json.dumps(pattern), State="ENABLED")
    ctx.on_cleanup(lambda: events.delete_rule(Name=name))
    return name


def _create_queue_for_rule(ctx, rule_arn: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-evfh-q-")
    url = sqs.create_queue(QueueName=name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return {"url": url, "arn": arn}


def _put_targets(ctx, rule_name: str, targets: list[dict[str, Any]]) -> None:
    events = ctx.client("events")
    ids = [t["Id"] for t in targets]
    # one target's RoleArn was just created; retry a nonzero FailedEntryCount to tolerate
    # IAM's eventual-consistency window before EventBridge can validate/assume the role
    deadline = time.monotonic() + 60.0
    while True:
        resp = events.put_targets(Rule=rule_name, Targets=targets)
        if resp.get("FailedEntryCount", 0) == 0:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"put_targets failed: {resp}")
        time.sleep(5.0)
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=ids))


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
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read().decode("utf-8")
            records.extend(_parse_concatenated_json(body))
    return records


def _deliver_until_firehose_receives(
    ctx, events_client, source: str, bucket: str, timeout_s: float = 140.0, attempt_timeout_s: float = 70.0
) -> tuple[str, list[dict]]:
    """Fires a fresh event and waits for it in S3 via the Firehose target, retrying with a new
    event on timeout. The events role and the firehose role were just created; EventBridge's
    async target invocation and Firehose's own S3 delivery each retry a failed attempt for only
    a bounded period rather than indefinitely, so a single event fired too soon after either
    role's creation can permanently miss the IAM propagation window."""
    deadline = time.monotonic() + timeout_s
    while True:
        marker = ctx.unique_name("marker-")
        events_client.put_events(
            Entries=[
                {
                    "Source": source,
                    "DetailType": "sim2real.test.fanout",
                    "Detail": json.dumps({"marker": marker}),
                }
            ]
        )
        attempt_deadline = min(deadline, time.monotonic() + attempt_timeout_s)
        while True:
            records = _list_bucket_records(ctx, bucket)
            matched = [r for r in records if r.get("detail", {}).get("marker") == marker]
            if matched:
                return marker, matched
            if time.monotonic() >= attempt_deadline:
                break
            time.sleep(2)
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"event delivered to S3 via the Firehose target not met within {timeout_s}s; "
                f"last marker {marker!r}, records seen: {records!r}"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
