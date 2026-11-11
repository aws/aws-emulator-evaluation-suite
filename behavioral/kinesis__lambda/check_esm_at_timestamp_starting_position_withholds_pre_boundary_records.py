"""esm-at-timestamp-starting-position-withholds-pre-boundary-records."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "esm-at-timestamp-starting-position-withholds-pre-boundary-records"
GROUP = "e2e"
SERVICES = ["kinesis", "lambda"]

# The post-boundary records are the twin control on identical wiring, so no calibrated absence
# window is needed; every record's ApproximateArrivalTimestamp is read back to prove the boundary
# separates the two groups by server-side time.

_PRE_PAYLOADS = tuple(f"pre-{i}" for i in range(4))
_POST_PAYLOADS = tuple(f"post-{i}" for i in range(4))
_PARTITION_KEY = "boundary-pk"
_PREFIX = "seen/"
_RUNTIME = "python3.12"
#: Seconds of clearance on each side of the boundary, so it is unambiguously between the groups.
_BOUNDARY_MARGIN_S = 3.0
_DELIVERY_BUDGET_S = 300.0

# The consumer's own source. The boto3.client() below runs INSIDE the deployed Lambda under its
# execution role — it is not one of this check's clients, all of which come from ctx.client(...).
_HANDLER_SOURCE = """
import base64
import os

import boto3

_S3 = boto3.client("s3")
_BUCKET = os.environ["BUCKET"]
_PREFIX = os.environ["PREFIX"]


def handler(event, context):
    for record in event["Records"]:
        payload = base64.b64decode(record["kinesis"]["data"]).decode()
        _S3.put_object(
            Bucket=_BUCKET,
            Key=_PREFIX + payload,
            Body=record["kinesis"]["sequenceNumber"].encode(),
        )
    return {"seen": len(event["Records"])}
"""


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c4",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Kinesis event source mapping pinned to AT_TIMESTAMP withholds every record written before
    that timestamp from the Lambda consumer, while records written after it arrive on the same
    wiring in the same run — and the withheld records are still on the stream."""
    kinesis = ctx.client("kinesis")
    s3 = ctx.client("s3")

    stream = _create_active_stream(ctx)
    shard_id = _single_shard_id(ctx, stream["name"])
    bucket = _create_bucket(ctx)

    for payload in _PRE_PAYLOADS:
        kinesis.put_record(
            StreamName=stream["name"], Data=payload.encode(), PartitionKey=_PARTITION_KEY
        )

    # ---- The boundary is derived from the SERVICE's own arrival timestamps, not the local clock ----
    pre_records = _read_records(ctx, stream["name"], shard_id, expect=len(_PRE_PAYLOADS))
    assert [r["Data"].decode() for r in pre_records] == list(_PRE_PAYLOADS), (
        f"the pre-boundary records read back as {[r['Data'] for r in pre_records]!r}; expected "
        f"{list(_PRE_PAYLOADS)!r}"
    )
    last_pre_arrival = max(r["ApproximateArrivalTimestamp"] for r in pre_records)
    boundary = last_pre_arrival + timedelta(seconds=_BOUNDARY_MARGIN_S)

    role_arn = _create_esm_role(ctx, stream["arn"], bucket)
    function = _create_function(ctx, role_arn, bucket)
    mapping_uuid = _create_mapping(ctx, function, stream["arn"], boundary)

    # Do not write the post records until the local clock is clearly past the boundary; the
    # separation is VERIFIED from server-side timestamps at the end, so this is only a head start.
    _poll_until(
        lambda: datetime.now(timezone.utc),
        lambda now: now > boundary + timedelta(seconds=_BOUNDARY_MARGIN_S),
        timeout_s=60.0,
        interval_s=1.0,
        description=(
            f"the clock to pass {boundary.isoformat()} plus {_BOUNDARY_MARGIN_S}s so the post-"
            "boundary records land unambiguously after the ESM's StartingPositionTimestamp"
        ),
    )
    for payload in _POST_PAYLOADS:
        kinesis.put_record(
            StreamName=stream["name"], Data=payload.encode(), PartitionKey=_PARTITION_KEY
        )
    posted_at = time.monotonic()

    # ---- The twin control: the post-boundary records DO arrive at the consumer ----
    _poll_until(
        lambda: _seen_payloads(s3, bucket),
        lambda seen: set(_POST_PAYLOADS).issubset(seen),
        timeout_s=_DELIVERY_BUDGET_S,
        interval_s=10.0,
        description=(
            f"all {len(_POST_PAYLOADS)} post-boundary records to reach the Lambda consumer and be "
            f"written to s3://{bucket}/{_PREFIX} (ESM {mapping_uuid})"
        ),
    )
    delivery_latency_s = max(time.monotonic() - posted_at, 1.0)

    # ---- Absence, on two independent observables at the consumer ----
    hold_deadline = time.monotonic() + delivery_latency_s
    while True:
        seen = _seen_payloads(s3, bucket)
        assert seen == set(_POST_PAYLOADS), (
            f"the consumer has seen {sorted(seen)}; expected exactly the post-boundary payloads "
            f"{sorted(_POST_PAYLOADS)}. Any of {sorted(_PRE_PAYLOADS)} means AT_TIMESTAMP delivered "
            "records written before StartingPositionTimestamp"
        )
        for payload in _PRE_PAYLOADS:
            code = _head_object_error_code(s3, bucket, _PREFIX + payload)
            assert code == "404", (
                f"HeadObject on s3://{bucket}/{_PREFIX}{payload} returned {code!r}; expected '404' "
                "— the pre-boundary record must never have reached the consumer"
            )
        if time.monotonic() >= hold_deadline:
            break
        # Held for one measured delivery latency past the twin's arrival; the twin control is the
        # barrier, this is confirmation, not the proof.
        time.sleep(5.0)

    # ---- The withheld records are still at the PRODUCER: withheld, not lost ----
    everything = _read_records(
        ctx, stream["name"], shard_id, expect=len(_PRE_PAYLOADS) + len(_POST_PAYLOADS)
    )
    payloads = [r["Data"].decode() for r in everything]
    assert payloads == list(_PRE_PAYLOADS) + list(_POST_PAYLOADS), (
        f"the stream holds {payloads!r}; expected all {len(payloads)} records in write order — the "
        "pre-boundary records were withheld from the consumer, not absent from the stream"
    )
    for record in everything:
        payload = record["Data"].decode()
        arrival = record["ApproximateArrivalTimestamp"]
        if payload in _PRE_PAYLOADS:
            assert arrival < boundary, (
                f"pre-boundary record {payload!r} has ApproximateArrivalTimestamp "
                f"{arrival.isoformat()}, which is NOT before the ESM's StartingPositionTimestamp "
                f"{boundary.isoformat()}; the absence above proves nothing unless the separation is "
                "real"
            )
        else:
            assert arrival > boundary, (
                f"post-boundary record {payload!r} has ApproximateArrivalTimestamp "
                f"{arrival.isoformat()}, which is NOT after the ESM's StartingPositionTimestamp "
                f"{boundary.isoformat()}"
            )



def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    """Bounded retry that RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}; last observation: {last!r}"
    )


def _create_active_stream(ctx, *, shard_count: int = 1) -> dict[str, str]:
    """Create-or-adopt a provisioned stream, tagged, and wait until it is ACTIVE."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-xsvc-kds-")
    try:
        kinesis.create_stream(
            StreamName=name,
            ShardCount=shard_count,
            StreamModeDetails={"StreamMode": "PROVISIONED"},
            Tags={"sim2real": "behavioral", "sim2real-check": CHECK},
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceInUseException":
            raise
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    )
    summary = _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
        lambda s: s["StreamStatus"] == "ACTIVE",
        timeout_s=240.0,
        interval_s=3.0,
        description=f"stream {name} to reach ACTIVE",
    )
    return {"name": name, "arn": summary["StreamARN"]}


def _single_shard_id(ctx, stream_name: str) -> str:
    kinesis = ctx.client("kinesis")

    def probe() -> list:
        try:
            return kinesis.list_shards(StreamName=stream_name)["Shards"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("ResourceInUseException", "ResourceNotFoundException"):
                return []
            raise

    shards = _poll_until(
        probe,
        lambda s: len(s) == 1,
        timeout_s=90.0,
        interval_s=3.0,
        description=f"exactly one shard to be addressable on {stream_name}",
    )
    return shards[0]["ShardId"]


def _create_bucket(ctx) -> str:
    """A tagged bucket, emptied then deleted on teardown."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-xsvc-obs-")
    kwargs: dict = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is the only region where CreateBucketConfiguration must be omitted.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={
            "TagSet": [
                {"Key": "sim2real", "Value": "behavioral"},
                {"Key": "sim2real-check", "Value": CHECK},
            ]
        },
    )

    def _teardown() -> None:
        token = None
        while True:
            list_kwargs: dict = {"Bucket": name}
            if token:
                list_kwargs["ContinuationToken"] = token
            page = s3.list_objects_v2(**list_kwargs)
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                s3.delete_objects(Bucket=name, Delete={"Objects": keys})
            if not page.get("IsTruncated"):
                break
            token = page["NextContinuationToken"]
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_teardown)
    return name


def _create_esm_role(ctx, stream_arn: str, bucket: str) -> str:
    """An execution role that can read the stream, write the bucket and write its own logs."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-xsvc-esm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[
            {"Key": "sim2real", "Value": "behavioral"},
            {"Key": "sim2real-check", "Value": CHECK},
        ],
    )["Role"]["Arn"]
    policy_name = "esm-and-s3"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "kinesis:DescribeStream",
                            "kinesis:DescribeStreamSummary",
                            "kinesis:GetRecords",
                            "kinesis:GetShardIterator",
                            "kinesis:ListShards",
                            "kinesis:ListStreams",
                        ],
                        "Resource": stream_arn,
                    },
                    {"Effect": "Allow", "Action": "kinesis:ListStreams", "Resource": "*"},
                    {
                        "Effect": "Allow",
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{bucket}/*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        "Resource": "*",
                    },
                ],
            }
        ),
    )
    # LIFO teardown: the inline policy must go before the role.
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return role_arn


def _create_function(ctx, role_arn: str, bucket: str) -> str:
    """Create the consumer Lambda, retrying through the IAM role-propagation window."""
    awslambda = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("index.py", _HANDLER_SOURCE)

    def _create():
        ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
        return awslambda.create_function(
            FunctionName=name,
            Runtime=_RUNTIME,
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": buffer.getvalue()},
            Timeout=30,
            Environment={"Variables": {"BUCKET": bucket, "PREFIX": _PREFIX}},
            Tags={"sim2real": "behavioral", "sim2real-check": CHECK},
        )

    deadline = time.monotonic() + 120.0
    while True:
        try:
            _create()
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceConflictException":
                break  # create-or-adopt: a re-run against the same name is fine.
            if code != "InvalidParameterValueException" or time.monotonic() >= deadline:
                raise
            time.sleep(5.0)
    ctx.on_cleanup(lambda: awslambda.delete_function(FunctionName=name))
    _poll_until(
        lambda: awslambda.get_function_configuration(FunctionName=name)["State"],
        lambda state: state == "Active",
        timeout_s=120.0,
        interval_s=3.0,
        description=f"lambda {name} to reach State=Active",
    )
    return name


def _create_mapping(ctx, function: str, stream_arn: str, boundary) -> str:
    """An AT_TIMESTAMP event source mapping, waited to Enabled."""
    awslambda = ctx.client("lambda")
    uuid = awslambda.create_event_source_mapping(
        FunctionName=function,
        EventSourceArn=stream_arn,
        StartingPosition="AT_TIMESTAMP",
        StartingPositionTimestamp=boundary,
        BatchSize=1,
        MaximumBatchingWindowInSeconds=0,
        Enabled=True,
    )["UUID"]
    ctx.on_cleanup(lambda: awslambda.delete_event_source_mapping(UUID=uuid))
    _poll_until(
        lambda: awslambda.get_event_source_mapping(UUID=uuid)["State"],
        lambda state: state == "Enabled",
        timeout_s=180.0,
        interval_s=5.0,
        description=f"event source mapping {uuid} to reach State=Enabled",
    )
    return uuid


def _seen_payloads(s3, bucket: str) -> set[str]:
    """Every payload the consumer recorded, across every page."""
    seen: set[str] = set()
    token = None
    while True:
        kwargs: dict = {"Bucket": bucket, "Prefix": _PREFIX}
        if token:
            kwargs["ContinuationToken"] = token
        page = s3.list_objects_v2(**kwargs)
        seen.update(o["Key"][len(_PREFIX) :] for o in page.get("Contents", []))
        if not page.get("IsTruncated"):
            return seen
        token = page["NextContinuationToken"]


def _head_object_error_code(s3, bucket: str, key: str) -> str:
    """The HeadObject error code; raises AssertionError if the object exists."""
    try:
        s3.head_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(
        f"HeadObject on s3://{bucket}/{key} succeeded; expected '404' "
        "— the pre-boundary record must never have reached the consumer"
    )


def _read_records(ctx, stream_name: str, shard_id: str, *, expect: int) -> list[dict]:
    """Read the shard from TRIM_HORIZON with a FRESH iterator; return every record read."""
    kinesis = ctx.client("kinesis")
    iterator = kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    collected: list[dict] = []
    state = {"iterator": iterator}

    def probe() -> int:
        resp = kinesis.get_records(ShardIterator=state["iterator"], Limit=1000)
        collected.extend(resp["Records"])
        state["iterator"] = resp.get("NextShardIterator") or state["iterator"]
        return len(collected)

    _poll_until(
        probe,
        lambda n: n >= expect,
        timeout_s=90.0,
        interval_s=1.0,
        description=f"{expect} records to be readable from {shard_id}",
    )
    return collected


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
