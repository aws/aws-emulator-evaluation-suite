"""input-template-reserved-pipe-variables-render-real-values."""
from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "input-template-reserved-pipe-variables-render-real-values"
GROUP = "data-transformation"
SERVICES = ["iam", "pipes", "sqs"]

_TEMPLATE = json.dumps(
    {
        "pipeArn": "<aws.pipes.pipe-arn>",
        "pipeName": "<aws.pipes.pipe-name>",
        "sourceArn": "<aws.pipes.source-arn>",
        "targetArn": "<aws.pipes.target-arn>",
        "ingestionTime": "<aws.pipes.event.ingestion-time>",
    }
)


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """The reserved InputTemplate variables <aws.pipes.pipe-arn>, <aws.pipes.pipe-name>,
    <aws.pipes.source-arn> and <aws.pipes.target-arn> render the pipe's real identifiers, and
    <aws.pipes.event.ingestion-time> renders a rising ISO 8601 timestamp across two records."""
    sqs = ctx.client("sqs")
    source = _create_queue(ctx)
    target = _create_queue(ctx)
    role = _create_pipe_role(ctx, source["arn"], target["arn"])

    pipe = _create_pipe(
        ctx,
        source=source["arn"],
        target=target["arn"],
        role_arn=role["arn"],
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        TargetParameters={"InputTemplate": _TEMPLATE},
    )
    pipe_arn = ctx.client("pipes").describe_pipe(Name=pipe)["Arn"]

    sqs.send_message(QueueUrl=source["url"], MessageBody=json.dumps({"n": 1}))
    first = _wait_for_messages(ctx, target["url"], expected_count=1, timeout_s=120)[0]["body"]

    expected_fixed = {
        "pipeArn": pipe_arn,
        "pipeName": pipe,
        "sourceArn": source["arn"],
        "targetArn": target["arn"],
    }
    first_fixed = {k: v for k, v in first.items() if k != "ingestionTime"}
    assert first_fixed == expected_fixed, f"rendered fixed fields {first_fixed!r} != expected {expected_fixed!r}"
    first_time = _parse_iso8601(first["ingestionTime"])

    sqs.send_message(QueueUrl=source["url"], MessageBody=json.dumps({"n": 2}))
    second = _wait_for_messages(ctx, target["url"], expected_count=1, timeout_s=120)[0]["body"]
    second_fixed = {k: v for k, v in second.items() if k != "ingestionTime"}
    assert second_fixed == expected_fixed, f"rendered fixed fields {second_fixed!r} != expected {expected_fixed!r}"
    second_time = _parse_iso8601(second["ingestionTime"])

    assert second_time >= first_time, (
        f"<aws.pipes.event.ingestion-time> must not go backwards between two records ingested in "
        f"order: first record's ingestion time {first['ingestionTime']!r} ({first_time.isoformat()}), "
        f"second record's {second['ingestionTime']!r} ({second_time.isoformat()})"
    )


def _parse_iso8601(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        return datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise AssertionError(f"<aws.pipes.event.ingestion-time> rendered {value!r}, not ISO 8601: {exc}") from exc


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
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=60.0, delete=True):
    sqs = ctx.client("sqs")
    messages: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(messages) < expected_count and time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=min(5, remaining),
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            messages.append({"body": body, "message_id": msg["MessageId"], "raw": msg["Body"]})
            if delete:
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    if len(messages) < expected_count:
        raise AssertionError(
            f"expected {expected_count} message(s) on {queue_url}, got {len(messages)} within "
            f"{timeout_s}s: {messages!r}"
        )
    return messages


def _create_queue(ctx) -> dict[str, str]:
    name = _xname(ctx, "q")
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, tags=_xsvc_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"name": name, "url": url, "arn": arn}


def _create_role(ctx, trust_service, inline_policy=None) -> dict[str, str]:
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Path="/sim2real/", Tags=_xsvc_tags_kv()
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy))
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


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


def _create_pipe_role(ctx, source_arn: str, target_arn: str, extra=None) -> dict[str, str]:
    statements = [
        {
            "Effect": "Allow",
            "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
            "Resource": source_arn,
        },
        {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arn},
    ]
    statements.extend(extra or [])
    return _create_role(ctx, "pipes.amazonaws.com", {"Version": "2012-10-17", "Statement": statements})


def _create_pipe(ctx, *, source: str, target: str, role_arn: str, desired_state="RUNNING",
                  wait_for="RUNNING", **extra) -> str:
    """Create a pipe and wait for CurrentState==wait_for. Returns the pipe name."""
    pipes = ctx.client("pipes")
    name = _xname(ctx, "pipe")
    last_err = None
    for _ in range(8):
        try:
            pipes.create_pipe(
                Name=name, RoleArn=role_arn, Source=source, Target=target,
                DesiredState=desired_state, Tags=_xsvc_resource_tags(), **extra,
            )
            break
        except ClientError as exc:
            msg = str(exc)
            if "cannot be assumed" in msg or "iam:PassRole" in msg:
                last_err = exc
                time.sleep(5)
                continue
            raise
    else:
        raise AssertionError(f"could not create pipe {name}: {last_err}")
    ctx.on_cleanup(lambda: ctx.client("pipes").delete_pipe(Name=name))
    _poll_until(
        lambda: pipes.describe_pipe(Name=name).get("CurrentState"),
        lambda s: s == wait_for, timeout_s=240.0, interval_s=5.0, description=f"pipe {name} {wait_for}",
    )
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
