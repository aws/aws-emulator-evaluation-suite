"""kinesis-source-filter-on-decoded-data-field-and-input-template-rendering."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kinesis-source-filter-on-decoded-data-field-and-input-template-rendering"
GROUP = "data-transformation"
SERVICES = ["iam", "kinesis", "pipes", "sqs"]


@tags("axis:negative-delivery", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A FilterCriteria pattern on a decoded Kinesis ``data`` sub-field matches only a record whose
    data is valid JSON, and InputTemplate's ``<$.data...>`` renders the decoded value -- the raw
    UTF-8 text when the data is not JSON, never base64.
    """
    kinesis = ctx.client("kinesis")

    stream_a = _create_stream(ctx)
    target_a = _create_queue(ctx)
    role_a = _create_pipe_role(ctx, stream_arn=stream_a["arn"], target_arn=target_a["arn"])

    keep_pattern = {"data": {"kind": ["keep"]}}
    keep_template = {"k": "<$.data.kind>", "t": "<$.data.tag>"}
    _create_pipe(
        ctx,
        source=stream_a["arn"],
        target=target_a["arn"],
        role_arn=role_a["arn"],
        SourceParameters={
            "KinesisStreamParameters": {"StartingPosition": "TRIM_HORIZON", "BatchSize": 1},
            "FilterCriteria": {"Filters": [{"Pattern": json.dumps(keep_pattern)}]},
        },
        TargetParameters={"InputTemplate": json.dumps(keep_template)},
    )

    # One shard and one partition key keep the records in order: the last "keep" record is read
    # after the kind=drop and non-JSON records, so its arrival shows both were filtered out.
    nonce = _xname(ctx, "nonce")
    for payload in (
        json.dumps({"kind": "keep", "tag": "first", "nonce": nonce}).encode("utf-8"),
        json.dumps({"kind": "drop", "tag": "dropped", "nonce": nonce}).encode("utf-8"),
        f"plain-text-{nonce}".encode("utf-8"),
        json.dumps({"kind": "keep", "tag": "last", "nonce": nonce}).encode("utf-8"),
    ):
        _put_record_when_ready(ctx, kinesis, stream_a["name"], payload, nonce)

    expected = [{"k": "keep", "t": "first"}, {"k": "keep", "t": "last"}]
    timeout_s = _budget_s(ctx, 180.0)
    deadline = time.monotonic() + timeout_s
    # Each rendered body is unique per source record (distinct "t"), so a set of bodies drops the
    # at-least-once duplicates of one record and keeps every distinct record that arrived.
    bodies: set[str] = set()
    parsed: list = []
    while time.monotonic() < deadline and not all(e in parsed for e in expected):
        bodies.update(_receive_once(ctx, target_a["url"]))
        parsed = [json.loads(b) for b in sorted(bodies)]
    if not all(e in parsed for e in expected) and _budget_spent(ctx):
        raise TimeoutError("the admitted records reaching the target: the run budget ended first; not graded")
    # A nested object pattern ({"data": {"kind": [...]}}) requires data to decode as JSON with that
    # shape, so the non-JSON record is filtered exactly like the kind=drop record.
    assert sorted(parsed, key=lambda b: str(b.get("t"))) == expected, (
        f"FilterCriteria {keep_pattern!r} must deliver exactly the two kind=keep records, rendered, "
        f"and filter the kind=drop and non-JSON records; within {timeout_s:.0f}s the target got {parsed!r}"
    )

    # A second, independent pipe: a filter that admits every record (a Kinesis record's
    # partitionKey always exists, whatever its data is) and a template that surfaces the decoded
    # data field directly, to observe how a non-JSON record's data renders once delivered.
    stream_b = _create_stream(ctx)
    target_b = _create_queue(ctx)
    role_b = _create_pipe_role(ctx, stream_arn=stream_b["arn"], target_arn=target_b["arn"])
    permissive_pattern = {"partitionKey": [{"exists": True}]}
    raw_template = {"d": "<$.data>"}
    _create_pipe(
        ctx,
        source=stream_b["arn"],
        target=target_b["arn"],
        role_arn=role_b["arn"],
        SourceParameters={
            "KinesisStreamParameters": {"StartingPosition": "TRIM_HORIZON", "BatchSize": 1},
            "FilterCriteria": {"Filters": [{"Pattern": json.dumps(permissive_pattern)}]},
        },
        TargetParameters={"InputTemplate": json.dumps(raw_template)},
    )

    probe_nonce = _xname(ctx, "probe")
    probe_text = f"plain-probe-{probe_nonce}"
    _put_record_when_ready(ctx, kinesis, stream_b["name"], probe_text.encode("utf-8"), probe_nonce)

    probe_start = time.monotonic()
    probe_deadline = probe_start + _budget_s(ctx, 180.0)
    probe_bodies: list[str] = []
    while time.monotonic() < probe_deadline and not probe_bodies:
        probe_bodies = sorted(set(_receive_once(ctx, target_b["url"])))
    if not probe_bodies and _budget_spent(ctx):
        raise TimeoutError("the probe record reaching the target: the run budget ended first; not graded")
    assert probe_bodies, f"the probe record never reached the target within {_budget_s(ctx, 180.0):.0f}s"
    probe_parsed = [json.loads(b) for b in probe_bodies]
    assert probe_parsed == [{"d": probe_text}], (
        f"a non-JSON Kinesis record's <$.data> must render the decoded UTF-8 text (never "
        f"base64-encoded, since the record already reached the target), expected "
        f"{{'d': {probe_text!r}}}, got {probe_parsed!r}"
    )


_PREFIX = "sim2real-kdt-"
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


def _receive_once(ctx, queue_url: str) -> list[str]:
    """One bounded long-poll receive; deletes what it reads and returns the raw message bodies."""
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    out = []
    for msg in resp.get("Messages", []):
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        out.append(msg["Body"])
    return out


def _create_stream(ctx) -> dict[str, str]:
    """Create a 1-shard Kinesis stream, register its teardown, and return {name, arn}."""
    kinesis = ctx.client("kinesis")
    name = _xname(ctx, "stream")
    kinesis.create_stream(StreamName=name, ShardCount=1, Tags=dict(_MANAGED))
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name))
    arn = _poll_until(
        ctx,
        lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
        lambda s: s.get("StreamStatus") == "ACTIVE",
        cap_s=180.0,
        interval_s=5.0,
        description=f"stream {name} ACTIVE",
    )["StreamARN"]
    return {"name": name, "arn": arn}


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
                DesiredState="RUNNING", Tags=dict(_MANAGED), **extra,
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


_TRANSITIONAL_PIPE_STATES = ("CREATING", "UPDATING", "STARTING", "STOPPING", "DELETING")


def _delete_pipe(ctx, name: str) -> None:
    """DeletePipe; a ConflictException is retried only while the pipe reads as transitional."""
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + 60.0
    while True:
        try:
            pipes.delete_pipe(Name=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "ConflictException" or time.monotonic() > deadline:
                raise
            try:
                state = pipes.describe_pipe(Name=name)["CurrentState"]
            except ClientError as describe_exc:
                if describe_exc.response["Error"]["Code"] == "NotFoundException":
                    return
                raise
            if state not in _TRANSITIONAL_PIPE_STATES:
                raise
            time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
