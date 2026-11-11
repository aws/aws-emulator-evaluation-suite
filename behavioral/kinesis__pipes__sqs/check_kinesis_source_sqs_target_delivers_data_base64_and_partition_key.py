"""kinesis-source-sqs-target-delivers-data-base64-and-partition-key."""
from __future__ import annotations

import base64
import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kinesis-source-sqs-target-delivers-data-base64-and-partition-key"
GROUP = "data-plane"
SERVICES = ["kinesis", "pipes", "sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Kinesis-stream source delivers each record to an SQS target as its own message carrying
    the record's raw bytes as base64 ``data`` and its exact ``partitionKey``, one record per
    message even while BatchSize polls several records from the stream at once.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-event-source.html
    """
    kinesis = ctx.client("kinesis")
    sqs = ctx.client("sqs")

    stream_name = _xname(ctx, "stream")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1, Tags=dict(_MANAGED))
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name))
    stream_arn = _poll_until(
        ctx,
        lambda: kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"],
        lambda s: s.get("StreamStatus") == "ACTIVE",
        cap_s=180.0,
        interval_s=5.0,
        description=f"stream {stream_name} ACTIVE",
    )["StreamARN"]

    nonce = _xname(ctx, "nonce")
    n_records = 5
    records = [
        {
            "pk": f"{nonce}-pk-{i}",
            "data": json.dumps({"nonce": nonce, "i": i}).encode("utf-8"),
        }
        for i in range(n_records)
    ]
    for rec in records:
        _put_record_when_ready(ctx, kinesis, stream_name, rec["data"], rec["pk"])

    target = _create_queue(ctx)
    role = _create_pipe_role(ctx, stream_arn=stream_arn, target_arn=target["arn"])

    # BatchSize=2 polls several records per GetRecords call even though 5 were written, so a
    # single-record SQS delivery proves the cap governs the poll, not the target invocation.
    pipe = _create_pipe(
        ctx,
        source=stream_arn,
        target=target["arn"],
        role_arn=role["arn"],
        SourceParameters={
            "KinesisStreamParameters": {"StartingPosition": "TRIM_HORIZON", "BatchSize": 2}
        },
    )

    want = {r["pk"] for r in records}
    by_pk: dict[str, dict] = {}
    arrays: list[Any] = []
    delivery_wait_s = _budget_s(ctx, 180.0)
    deadline = time.monotonic() + delivery_wait_s
    while time.monotonic() < deadline and set(by_pk) != want:
        resp = sqs.receive_message(QueueUrl=target["url"], MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=target["url"], ReceiptHandle=msg["ReceiptHandle"])
            payload = json.loads(msg["Body"])
            if isinstance(payload, list):
                arrays.append(payload)
                continue
            if payload.get("partitionKey") not in want:
                continue
            by_pk[payload["partitionKey"]] = payload
    if set(by_pk) != want and _budget_spent(ctx):
        raise TimeoutError("every record reaching the SQS target: the run budget ended first; not graded")

    assert set(by_pk) == want, (
        f"every put record must reach the SQS target exactly once; missing "
        f"{sorted(want - set(by_pk))!r}, got {sorted(by_pk)!r}"
    )
    assert arrays == [], (
        f"an SQS target receives one Kinesis record per message, never a JSON array of records; "
        f"saw {len(arrays)} array-shaped delivery/deliveries: {arrays!r}"
    )
    for rec in records:
        envelope = by_pk[rec["pk"]]
        assert envelope["eventSource"] == "aws:kinesis", (
            f"record {rec['pk']!r} envelope has eventSource={envelope.get('eventSource')!r}, "
            f"expected 'aws:kinesis'"
        )
        assert envelope["eventSourceARN"] == stream_arn, (
            f"record {rec['pk']!r} envelope has eventSourceARN={envelope.get('eventSourceARN')!r}, "
            f"expected the source stream {stream_arn!r}"
        )
        assert envelope["partitionKey"] == rec["pk"], (
            f"record envelope partitionKey={envelope.get('partitionKey')!r}, expected {rec['pk']!r}"
        )
        decoded = base64.b64decode(envelope["data"])
        assert decoded == rec["data"], (
            f"record {rec['pk']!r} delivered data decodes to {decoded!r}, expected the exact "
            f"bytes put to the stream {rec['data']!r}"
        )


_PREFIX = "sim2real-kdp-"
_MANAGED = {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name so any leftover can be found by tag or prefix."""
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED.items()]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _expired(ctx, description, timeout_s, detail):
    """The error for a capped wait that ran out: TimeoutError when the run budget ended it."""
    if _budget_spent(ctx):
        return TimeoutError(f"{description}: the run budget ended first; not graded")
    return AssertionError(f"{description}: not met within {timeout_s:.0f}s; {detail}")


def _poll_until(ctx, probe, predicate, *, cap_s: float, interval_s: float, description: str):
    """Poll probe() until predicate(result), under a deadline capped by the run budget."""
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise _expired(ctx, description, timeout_s, f"last: {last!r}")


def _put_record_when_ready(ctx, kinesis, name: str, payload: bytes, partition_key: str,
                           cap_s: float = 30.0):
    """DescribeStreamSummary reporting ACTIVE precedes full data-plane routing readiness by a few
    seconds on real AWS; PutRecord can still answer ResourceNotFoundException right afterward."""
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return kinesis.put_record(StreamName=name, Data=payload, PartitionKey=partition_key)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            if time.monotonic() >= deadline:
                raise _expired(ctx, f"PutRecord accepted by {name}", timeout_s, f"last error: {exc}") from exc
            time.sleep(1)


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = _xname(ctx, "q")
    url = sqs.create_queue(QueueName=name, tags=dict(_MANAGED))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"name": name, "url": url, "arn": arn}


def _create_pipe_role(ctx, *, stream_arn: str, target_arn: str) -> dict[str, str]:
    iam = ctx.client("iam")
    role_name = _xname(ctx, "role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "pipes.amazonaws.com"},
             "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Path="/sim2real/",
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "kinesis:DescribeStream", "kinesis:DescribeStreamSummary", "kinesis:GetRecords",
                "kinesis:GetShardIterator", "kinesis:ListShards", "kinesis:ListStreams",
                "kinesis:SubscribeToShard",
            ],
            "Resource": stream_arn,
        },
        {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": target_arn},
    ]
    iam.put_role_policy(
        RoleName=role_name, PolicyName="pipe-inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return {"name": role_name, "arn": arn}


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_pipe(ctx, *, source: str, target: str, role_arn: str, **extra: Any) -> str:
    pipes = ctx.client("pipes")
    name = _xname(ctx, "pipe")
    timeout_s = _budget_s(ctx, 90.0)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            pipes.create_pipe(
                Name=name, RoleArn=role_arn, Source=source, Target=target,
                DesiredState="RUNNING", Tags=_MANAGED, **extra,
            )
            break
        except ClientError as exc:
            text = str(exc)
            if "cannot be assumed" not in text and "iam:PassRole" not in text:
                raise
            if time.monotonic() >= deadline:
                raise _expired(ctx, f"pipe {name!r} role assumable", timeout_s, f"last error: {exc!r}") from exc
            time.sleep(3)
    ctx.on_cleanup(lambda: _delete_pipe(ctx, name))
    settled = _poll_until(
        ctx,
        lambda: pipes.describe_pipe(Name=name),
        lambda d: d.get("CurrentState") in ("RUNNING", "CREATE_FAILED", "START_FAILED"),
        cap_s=180.0,
        interval_s=5.0,
        description=f"pipe {name} RUNNING",
    )
    assert settled["CurrentState"] == "RUNNING", (
        f"pipe {name} settled in {settled['CurrentState']!r} ({settled.get('StateReason')!r})"
    )
    return name


def _delete_pipe(ctx, name: str) -> None:
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + 60.0
    while True:
        try:
            pipes.delete_pipe(Name=name)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("ConflictException", "NotFoundException"):
                raise
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            if time.monotonic() > deadline:
                raise
            time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
