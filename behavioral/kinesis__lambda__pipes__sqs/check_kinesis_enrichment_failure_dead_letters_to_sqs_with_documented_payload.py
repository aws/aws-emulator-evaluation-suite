"""kinesis-enrichment-failure-dead-letters-to-sqs-with-documented-payload."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kinesis-enrichment-failure-dead-letters-to-sqs-with-documented-payload"
GROUP = "error-propagation"
SERVICES = ["kinesis", "lambda", "pipes", "sqs"]

_ENRICH_CODE = """
def handler(event, context):
    raise RuntimeError("enrichment always fails")
"""


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Kinesis-source pipe with MaximumRetryAttempts=0 and an enrichment that always throws
    dead-letters the record to its SQS DeadLetterConfig target, with the record's batch
    identified by shard, sequence range and source stream rather than its own data.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-error-troubleshooting.html
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

    shard_ids = {s["ShardId"] for s in kinesis.describe_stream(StreamName=stream_name)[
        "StreamDescription"]["Shards"]}

    nonce = _xname(ctx, "nonce")
    pk = f"{nonce}-pk"
    data = json.dumps({"nonce": nonce}).encode("utf-8")
    _put_record_when_ready(ctx, kinesis, stream_name, data, pk)

    target = _create_queue(ctx)
    dlq = _create_queue(ctx)
    enrichment = _create_enrichment(ctx, _ENRICH_CODE)
    role = _create_pipe_role(ctx, stream_arn=stream_arn, target_arn=target["arn"],
                             dlq_arn=dlq["arn"], function_arn=enrichment["arn"])

    _, pipe_arn = _create_pipe(
        ctx,
        source=stream_arn,
        target=target["arn"],
        role_arn=role["arn"],
        Enrichment=enrichment["arn"],
        SourceParameters={"KinesisStreamParameters": {
            "StartingPosition": "TRIM_HORIZON",
            "BatchSize": 1,
            "MaximumRetryAttempts": 0,
            "OnPartialBatchItemFailure": "AUTOMATIC_BISECT",
            "DeadLetterConfig": {"Arn": dlq["arn"]},
        }},
    )

    dlq_wait_s = _budget_s(ctx, 240.0)
    deadline = time.monotonic() + dlq_wait_s
    letters: list[dict] = []
    while time.monotonic() < deadline and not letters:
        resp = sqs.receive_message(QueueUrl=dlq["url"], MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=dlq["url"], ReceiptHandle=msg["ReceiptHandle"])
            letters.append(json.loads(msg["Body"]))
    if not letters:
        raise _expired(ctx, "a dead letter on the pipe's DLQ", dlq_wait_s, "the DLQ stayed empty")
    # Keep draining for a quiet window so a second copy of the dead letter is counted too.
    for body in _drain_nowait(ctx, dlq["url"]):
        letters.append(json.loads(body))

    assert len(letters) == 1, (
        f"a single always-failing record with MaximumRetryAttempts=0 must dead-letter as one "
        f"message; the DLQ carried {len(letters)}: {letters!r}"
    )
    letter = letters[0]
    assert letter.get("context") == {
        "partnerResourceArn": pipe_arn, "condition": "RetryAttemptsExhausted"
    }, (
        f"the dead letter's context must name this pipe and RetryAttemptsExhausted, got "
        f"{letter.get('context')!r}, expected pipe {pipe_arn!r}"
    )
    assert letter.get("version") == "1.0", f"dead letter version was {letter.get('version')!r}"
    batch_info = letter.get("KinesisBatchInfo")
    assert isinstance(batch_info, dict), f"dead letter has no KinesisBatchInfo: {letter!r}"
    assert batch_info.get("streamArn") == stream_arn, (
        f"KinesisBatchInfo.streamArn was {batch_info.get('streamArn')!r}, expected the source "
        f"stream {stream_arn!r}"
    )
    assert batch_info.get("shardId") in shard_ids, (
        f"KinesisBatchInfo.shardId {batch_info.get('shardId')!r} is not one of the stream's own "
        f"shards {sorted(shard_ids)!r}"
    )
    assert batch_info.get("batchSize") == 1, (
        f"KinesisBatchInfo.batchSize was {batch_info.get('batchSize')!r}, expected 1 record"
    )
    assert batch_info.get("startSequenceNumber") == batch_info.get("endSequenceNumber"), (
        f"a batch of one record must report the same start and end sequence number, got "
        f"{batch_info.get('startSequenceNumber')!r} and {batch_info.get('endSequenceNumber')!r}"
    )
    assert batch_info.get("startSequenceNumber", "").isdigit(), (
        f"KinesisBatchInfo.startSequenceNumber must be a decimal sequence number, got "
        f"{batch_info.get('startSequenceNumber')!r}"
    )

    leaked = _drain_nowait(ctx, target["url"])
    assert leaked == [], (
        f"a record whose enrichment always throws must never reach the target; target carried "
        f"{leaked!r}"
    )


_PREFIX = "sim2real-kef-"
_MANAGED = {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


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


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name so any leftover can be found by tag or prefix."""
    return ctx.unique_name(f"{_PREFIX}{kind}-")


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


def _create_role(ctx, service: str, statements: list[dict]) -> dict[str, str]:
    iam = ctx.client("iam")
    name = _xname(ctx, "role")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Path="/sim2real/",
                          Tags=[{"Key": k, "Value": v} for k, v in _MANAGED.items()])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    if statements:
        iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": statements}))
    return {"name": name, "arn": arn}


def _delete_role(ctx, name: str) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=p)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _reap_log_group(ctx, fn_name: str) -> None:
    """Delete /aws/lambda/<fn> until it stops reappearing (a buffered stream can recreate it)."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{fn_name}"
    for _ in range(4):
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        deadline = time.monotonic() + 8
        reappeared = False
        while time.monotonic() < deadline:
            found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
            if any(g["logGroupName"] == group for g in found):
                reappeared = True
                break
            time.sleep(2)
        if not reappeared:
            return
    raise AssertionError(f"log group {group} kept reappearing after delete")


def _create_enrichment(ctx, code: str) -> dict[str, str]:
    """A python Lambda used as the pipe's enrichment; it always raises."""
    role = _create_role(ctx, "lambda.amazonaws.com", [])
    lam = ctx.client("lambda")
    name = _xname(ctx, "fn")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(code))
    ctx.on_cleanup(lambda: _reap_log_group(ctx, name))
    timeout_s = _budget_s(ctx, 60.0)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.13", Role=role["arn"],
                Handler="index.handler", Code={"ZipFile": buf.getvalue()},
                Timeout=30, MemorySize=128, Tags=dict(_MANAGED),
            )["FunctionArn"]
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "InvalidParameterValueException" or "cannot be assumed" not in err.get("Message", ""):
                raise
            if time.monotonic() >= deadline:
                raise _expired(ctx, f"lambda {name} role assumable", timeout_s, f"last error: {err!r}") from exc
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        ctx,
        lambda: lam.get_function_configuration(FunctionName=name).get("State"),
        lambda s: s == "Active", cap_s=90.0, interval_s=3.0,
        description=f"lambda {name} Active",
    )
    return {"name": name, "arn": arn}


def _create_pipe_role(ctx, *, stream_arn: str, target_arn: str, dlq_arn: str,
                      function_arn: str) -> dict[str, str]:
    return _create_role(ctx, "pipes.amazonaws.com", [
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
        {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": dlq_arn},
        {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": function_arn},
    ])


def _create_pipe(ctx, *, source: str, target: str, role_arn: str, **extra: Any) -> tuple[str, str]:
    pipes = ctx.client("pipes")
    name = _xname(ctx, "pipe")
    timeout_s = _budget_s(ctx, 90.0)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            created = pipes.create_pipe(
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
    state = _poll_until(
        ctx,
        lambda: pipes.describe_pipe(Name=name),
        lambda d: d.get("CurrentState") in ("RUNNING", "CREATE_FAILED", "START_FAILED"),
        cap_s=180.0,
        interval_s=5.0,
        description=f"pipe {name} RUNNING",
    )
    assert state["CurrentState"] == "RUNNING", (
        f"pipe {name} settled in {state['CurrentState']!r} ({state.get('StateReason')!r})"
    )
    return name, created["Arn"]


def _drain_nowait(ctx, url: str, window_s: float = 20.0) -> list[Any]:
    """Receive and delete for a bounded window: one receive can miss a message SQS has not yet
    surfaced, so absence is only shown by several empty long polls."""
    sqs = ctx.client("sqs")
    got: list[Any] = []
    deadline = time.monotonic() + _budget_s(ctx, window_s)
    while time.monotonic() < deadline:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                     WaitTimeSeconds=5).get("Messages", []):
            got.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return got


def _delete_pipe(ctx, name: str) -> None:
    pipes = ctx.client("pipes")
    try:
        pipes.delete_pipe(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NotFoundException":
            return
        raise
    deadline = time.monotonic() + 50.0
    while time.monotonic() < deadline:
        try:
            pipes.describe_pipe(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(3)
    raise AssertionError(f"pipe {name} still present 50s after DeletePipe")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
