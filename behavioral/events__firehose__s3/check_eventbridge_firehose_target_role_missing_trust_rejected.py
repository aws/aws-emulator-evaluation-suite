"""eventbridge-firehose-target-role-missing-trust-rejected."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-firehose-target-role-missing-trust-rejected"
GROUP = "overly-permissive"
SERVICES = ["events", "firehose", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags(
    "axis:negative-delivery",
    "cap:c4",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A rule whose Firehose target role has firehose:PutRecord but does not trust events.amazonaws.com never
    gets its event into the stream's S3 destination, while a sibling rule whose role trusts it delivers."""
    bucket = _create_bucket(ctx)
    fh_role_arn = _create_firehose_role(ctx, _bucket_arn(bucket))
    stream = _create_delivery_stream(ctx, _bucket_arn(bucket), fh_role_arn)

    good_role_arn = _create_events_role(
        ctx, stream_arns=[stream["arn"]], trusted_service="events.amazonaws.com"
    )
    # Has the correct firehose permissions, but trusts the WRONG principal -- events.amazonaws.com
    # can never assume it.
    bad_role_arn = _create_events_role(
        ctx, stream_arns=[stream["arn"]], trusted_service="lambda.amazonaws.com"
    )

    source_good = ctx.unique_name("sim2real-evfh-src-good-")
    source_bad = ctx.unique_name("sim2real-evfh-src-bad-")
    rule_good = _create_rule(ctx, {"source": [source_good]})
    rule_bad = _create_rule(ctx, {"source": [source_bad]})
    _put_target(
        ctx,
        rule_good,
        {"Id": "firehose-target", "Arn": stream["arn"], "RoleArn": good_role_arn},
        "firehose-target",
    )
    _put_target(
        ctx,
        rule_bad,
        {"Id": "firehose-target", "Arn": stream["arn"], "RoleArn": bad_role_arn},
        "firehose-target",
    )

    marker_good = ctx.unique_name("marker-good-")
    marker_bad = ctx.unique_name("marker-bad-")
    events = ctx.client("events")
    events.put_events(
        Entries=[
            {
                "Source": source_good,
                "DetailType": "sim2real.test.trust",
                "Detail": json.dumps({"marker": marker_good}),
            },
            {
                "Source": source_bad,
                "DetailType": "sim2real.test.trust",
                "Detail": json.dumps({"marker": marker_bad}),
            },
        ]
    )

    # Positive control: wait for the correctly-trusted rule's event to land.
    records = _poll_for_records(
        ctx,
        bucket,
        lambda recs: any(
            r.get("detail", {}).get("marker") == marker_good for r in recs
        ),
        description="correctly-trusted rule's event delivered to S3 via Firehose",
    )
    good_matched = [
        r for r in records if r.get("detail", {}).get("marker") == marker_good
    ]
    assert len(good_matched) == 1, (
        f"expected exactly one control record, got {good_matched}"
    )

    bad_matched = [
        r for r in records if r.get("detail", {}).get("marker") == marker_bad
    ]
    assert bad_matched == [], (
        f"event was delivered despite the target role not trusting events.amazonaws.com: {bad_matched}"
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
        # S3 API quirk, not a region pin: us-east-1 rejects an explicit
        # LocationConstraint, so this branches on ctx.region rather than fixing one.
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    time.sleep(10.0)  # IAM role propagation is eventually consistent
    return role_arn


def _create_delivery_stream(
    ctx, bucket_arn: str, role_arn: str, prefix: str | None = None
) -> dict[str, str]:
    fh = ctx.client("firehose")
    name = ctx.unique_name("sim2real-fh-")
    s3_config: dict[str, Any] = {
        "RoleARN": role_arn,
        "BucketARN": bucket_arn,
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
    }
    if prefix:
        s3_config["Prefix"] = prefix
    # Bounded retry absorbs the firehose role's IAM propagation delay -- a fresh
    # role can make create_delivery_stream fail transiently until it is assumable.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            fh.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                S3DestinationConfiguration=s3_config,
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
            break
        except ClientError:
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
    time.sleep(10.0)  # IAM role propagation is eventually consistent
    return role_arn


def _create_rule(ctx, pattern: dict[str, Any]) -> str:
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-evfh-rule-")
    rule_arn = events.put_rule(
        Name=name, EventPattern=json.dumps(pattern), State="ENABLED"
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=name))
    events.tag_resource(
        ResourceARN=rule_arn, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
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


def _poll_for_records(
    ctx,
    bucket: str,
    predicate,
    timeout_s: float = 240.0,
    interval_s: float = 15.0,
    description: str = "records in S3",
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
