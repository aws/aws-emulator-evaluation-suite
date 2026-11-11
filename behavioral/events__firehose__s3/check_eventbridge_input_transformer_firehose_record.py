"""eventbridge-input-transformer-firehose-record."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-input-transformer-firehose-record"
GROUP = "data-format"
SERVICES = ["events", "firehose", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """When a rule's target has an InputTransformer, the record Firehose actually receives (and
    delivers to S3) is exactly the transformer's rendered output -- not the raw event envelope."""
    bucket = _create_bucket(ctx)
    fh_role_arn = _create_firehose_role(ctx, _bucket_arn(bucket))
    stream = _create_delivery_stream(ctx, _bucket_arn(bucket), fh_role_arn)
    ev_role_arn = _create_events_role(ctx, stream_arns=[stream["arn"]])

    source = ctx.unique_name("sim2real-evfh-src-")
    rule_name = _create_rule(ctx, {"source": [source]})

    transformer = {
        "InputPathsMap": {
            "detailMarker": "$.detail.marker",
            "detailMsg": "$.detail.message",
        },
        "InputTemplate": (
            '{"transformedMarker": "<detailMarker>", "note": "<detailMsg>", '
            '"fixedField": "sim2real-fixed"}'
        ),
    }
    _put_target(
        ctx,
        rule_name,
        {
            "Id": "firehose-target",
            "Arn": stream["arn"],
            "RoleArn": ev_role_arn,
            "InputTransformer": transformer,
        },
        "firehose-target",
    )

    events = ctx.client("events")

    # PutTargets accepts RoleArn without validating it is assumable, so the rule can be
    # live before events.amazonaws.com's cross-service propagation of the new role's trust
    # policy completes -- and EventBridge does not visibly retry an invoke that fails for
    # that reason. Rather than sleep blindly for an assumed propagation window, fire a fresh
    # event per attempt and let each attempt's own bounded poll be the evidence: the
    # attempt that lands ends the retry, so the wait is bounded to what real AWS actually
    # took, not a guessed constant.
    marker = None
    records = None
    attempts = [(90.0, 10.0), (120.0, 10.0), (150.0, 10.0)]
    for timeout_s, interval_s in attempts:
        marker = ctx.unique_name("marker-")
        events.put_events(
            Entries=[
                {
                    "Source": source,
                    "DetailType": "sim2real.test.transform",
                    "Detail": json.dumps({"marker": marker, "message": "hello-transform"}),
                }
            ]
        )
        records = _records_within(
            ctx,
            bucket,
            lambda recs: any(r.get("transformedMarker") == marker for r in recs),
            timeout_s=timeout_s,
            interval_s=interval_s,
        )
        if records is not None:
            break
    if records is None:
        raise AssertionError(
            f"input-transformer output never delivered to S3 via Firehose after "
            f"{len(attempts)} attempts; last marker {marker!r}"
        )

    matched = [r for r in records if r.get("transformedMarker") == marker]
    assert len(matched) == 1, f"expected exactly one transformed record, got {matched}"
    record = matched[0]
    # The delivered body must be EXACTLY the transformer's output shape -- no envelope fields.
    assert record == {
        "transformedMarker": marker,
        "note": "hello-transform",
        "fixedField": "sim2real-fixed",
    }, f"unexpected record shape: {record}"


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
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint.
    if ctx.region == "us-east-1":
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
            }
        ],
    }
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    # No IAM signal indicates cross-service assume-role propagation; _create_delivery_stream's
    # own create-with-retry loop (below) is the bounded wait that absorbs the lag.
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
                Tags=[{"Key": "sim2real", "Value": CHECK}],
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
            RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy)
        )
        ctx.on_cleanup(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        )
    # PutTargets does not validate assume-role at configure time; EventBridge validates (and
    # retries on failure) at invoke time, which the per-attempt delivery deadlines in run() absorb.
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
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read().decode("utf-8")
            records.extend(_parse_concatenated_json(body))
    return records


def _records_within(
    ctx, bucket: str, predicate, *, timeout_s: float, interval_s: float
) -> list[dict] | None:
    """Return the bucket's records once predicate(records) holds, or None at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        records = _list_bucket_records(ctx, bucket)
        if predicate(records):
            return records
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
