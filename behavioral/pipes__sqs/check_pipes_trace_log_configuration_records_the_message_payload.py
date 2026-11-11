"""pipes-trace-log-configuration-records-the-message-payload."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipes-trace-log-configuration-records-the-message-payload"

GROUP = "observability"

SERVICES = ["pipes", "sqs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing",
      "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Level=TRACE, IncludeExecutionData=['ALL'] pipe writes execution log records that name the
    pipe, carry the source message's payload and include TRACE-level records, while a string never
    sent through the pipe is absent from the group.
    """
    sqs = ctx.client("sqs")
    logs = ctx.client("logs")
    source = _create_queue(ctx, VisibilityTimeout="60")
    target = _create_queue(ctx)

    log_group = f"/aws/vendedlogs/pipes/{_xname(ctx, 'lg')}"
    logs.create_log_group(logGroupName=log_group, tags=_xsvc_resource_tags())
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    described = logs.describe_log_groups(logGroupNamePrefix=log_group)["logGroups"]
    assert described, f"log group {log_group!r} was created but does not describe"
    # Pipes wants the group ARN without the trailing ':*' that DescribeLogGroups appends.
    log_group_arn = described[0]["arn"].rstrip("*").rstrip(":")

    role = _create_pipe_role(
        ctx,
        source["arn"],
        target["arn"],
        extra=[
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": [log_group_arn, log_group_arn + ":*"],
            }
        ],
    )

    pipe = _create_pipe(
        ctx,
        source=source["arn"],
        target=target["arn"],
        role_arn=role["arn"],
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        LogConfiguration={
            "CloudwatchLogsLogDestination": {"LogGroupArn": log_group_arn},
            "Level": "TRACE",
            "IncludeExecutionData": ["ALL"],
        },
    )

    nonce = _xname(ctx, "logmark")
    never_sent = _xname(ctx, "neversent")
    sqs.send_message(QueueUrl=source["url"], MessageBody=json.dumps({"marker": nonce}))
    delivered = _wait_for_messages(ctx, target["url"], expected_count=1, timeout_s=150)[0]
    assert nonce in delivered["raw"], (
        f"the pipe must deliver before its execution log can be asserted; the target got "
        f"{delivered['raw']!r} instead of a record carrying {nonce!r}"
    )

    # The payload-bearing record identifies the execution; every record of that execution is then
    # read back, which is where the TRACE-only records live.
    payload_events = _poll_until(
        lambda: logs.filter_log_events(logGroupName=log_group, filterPattern=f'"{nonce}"').get(
            "events", []
        ),
        lambda evs: bool(evs),
        timeout_s=150.0,
        interval_s=5.0,
        description=f"an execution log record carrying the payload {nonce!r} in {log_group!r}",
    )
    payload_record = json.loads(payload_events[0]["message"])
    assert nonce in payload_events[0]["message"], (
        f"the matched log event must carry the source payload {nonce!r}: {payload_events[0]!r}"
    )
    assert nonce in payload_record.get("payload", ""), (
        f"IncludeExecutionData=['ALL'] must put the source record in the record's own payload "
        f"field, not merely somewhere in the log line: {payload_record!r}"
    )
    assert pipe in payload_record.get("resourceArn", ""), (
        f"the execution record must name the pipe {pipe!r} in its resourceArn, got "
        f"{payload_record.get('resourceArn')!r} in {payload_record!r}"
    )
    execution_id = payload_record["executionId"]

    records = _poll_until(
        lambda: [
            json.loads(e["message"])
            for e in logs.filter_log_events(
                logGroupName=log_group, filterPattern=f'"{execution_id}"'
            ).get("events", [])
        ],
        lambda recs: any(r.get("logLevel") == "TRACE" for r in recs),
        timeout_s=150.0,
        interval_s=5.0,
        description=f"a logLevel=TRACE record for execution {execution_id!r}",
    )
    levels = {r.get("logLevel") for r in records}
    assert "TRACE" in levels, (
        f"a Level=TRACE pipe must emit at least one logLevel=TRACE record for execution "
        f"{execution_id!r}; the levels observed were {sorted(levels)!r} over {records!r}"
    )
    assert all(pipe in r.get("resourceArn", "") for r in records), (
        f"every record of execution {execution_id!r} must name the pipe {pipe!r}: "
        f"{[r.get('resourceArn') for r in records]!r}"
    )
    assert {r.get("executionId") for r in records} == {execution_id}, (
        f"the execution-id search must return records for that execution only, got "
        f"{sorted({r.get('executionId') for r in records})!r}"
    )

    control = logs.filter_log_events(
        logGroupName=log_group, filterPattern=f'"{never_sent}"'
    ).get("events", [])
    assert control == [], (
        f"the log group holds a record for {never_sent!r}, a marker that was never sent through the "
        f"pipe: {control!r}"
    )

# ===== helpers (self-contained) =====
_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=60.0, delete=True):
    """Poll SQS until expected_count messages arrive; return them (raises on timeout)."""
    sqs = ctx.client("sqs")
    messages: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(messages) < expected_count and time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=min(5, remaining),
            AttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            messages.append(
                {
                    "body": body,
                    "message_id": msg["MessageId"],
                    "raw": msg["Body"],
                    "attributes": msg.get("Attributes", {}),
                }
            )
            if delete:
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    if len(messages) < expected_count:
        raise AssertionError(
            f"expected {expected_count} message(s) on {queue_url}, got {len(messages)} within "
            f"{timeout_s}s: {messages!r}"
        )
    return messages


def _drain(ctx, queue_url, window_s=20.0):
    """Receive everything that shows up on a queue inside a bounded window; return raw bodies."""
    sqs = ctx.client("sqs")
    seen: list[str] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        msgs = resp.get("Messages", [])
        for msg in msgs:
            seen.append(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return seen


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags())
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _create_role(ctx, trust_service, inline_policy=None) -> dict[str, str]:
    """Create an IAM role and register its (policy-delete-then-role-delete) teardown."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every inline policy removed before deletion."""
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


def _create_pipe_role(ctx, source_arn: str, target_arn, extra=None) -> dict[str, str]:
    """The standard pipe execution role: read the source queue, send to the target queue(s)."""
    statements = [
        {
            "Effect": "Allow",
            "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
            "Resource": source_arn,
        },
        {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arn},
    ]
    statements.extend(extra or [])
    return _create_role(
        ctx, "pipes.amazonaws.com", {"Version": "2012-10-17", "Statement": statements}
    )


def _create_pipe(ctx, *, source: str, target: str, role_arn: str, desired_state="RUNNING",
                 wait_for="RUNNING", **extra) -> str:
    """Create a pipe and wait for CurrentState==wait_for. Returns the pipe name.

    Pipes assumes the role at create time, so a freshly-created role can lose the IAM propagation
    race; the bounded retry covers only the two assume-role messages, because retrying a
    ValidationException would turn a permanent rejection into a timeout.
    """
    pipes = ctx.client("pipes")
    name = _xname(ctx, "pipe")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            pipes.create_pipe(
                Name=name,
                RoleArn=role_arn,
                Source=source,
                Target=target,
                DesiredState=desired_state,
                Tags=_xsvc_resource_tags(),
                **extra,
            )
            break
        except ClientError as exc:
            msg = str(exc)
            if "cannot be assumed" in msg or "iam:PassRole" in msg:
                if time.monotonic() >= deadline:
                    raise AssertionError(f"could not create pipe {name}: {exc}") from exc
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(lambda: ctx.client("pipes").delete_pipe(Name=name))
    _poll_until(
        lambda: pipes.describe_pipe(Name=name).get("CurrentState"),
        lambda s: s == wait_for,
        timeout_s=240.0,
        interval_s=5.0,
        description=f"pipe {name} {wait_for}",
    )
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
