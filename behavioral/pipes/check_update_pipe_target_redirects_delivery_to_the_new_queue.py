"""update-pipe-target-redirects-delivery-to-the-new-queue."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-pipe-target-redirects-delivery-to-the-new-queue"
GROUP = "lifecycle"
SERVICES = ["pipes"]

_RES_TAGS = {"sim2real": CHECK}


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdatePipe with a new Target moves delivery: later records reach the new queue, not the old.

    After the update the pipe is RUNNING again, DescribePipe reports queue B, a second record
    reaches B, and queue A receives nothing more.
    """
    sqs = ctx.client("sqs")
    pipes = ctx.client("pipes")
    src_url, src_arn = _create_queue(ctx, "sim2real-pipes-retgt-src-")
    a_url, a_arn = _create_queue(ctx, "sim2real-pipes-retgt-a-")
    b_url, b_arn = _create_queue(ctx, "sim2real-pipes-retgt-b-")
    role_arn = _create_pipe_role(ctx, _sqs_pipe_statements([src_arn], [a_arn, b_arn]))

    name = ctx.unique_name("sim2real-pipes-retgt-")
    template = {"InputTemplate": "<$.body>"}
    _create_pipe_with_retry(
        ctx, Name=name, RoleArn=role_arn, Source=src_arn, Target=a_arn,
        TargetParameters=template, DesiredState="RUNNING", Tags=_RES_TAGS,
    )
    desc = _wait_state(ctx, name, {"RUNNING", "STOPPED", "CREATE_FAILED"})
    assert desc["CurrentState"] == "RUNNING", (
        f"pipe settled in {desc['CurrentState']!r} ({desc.get('StateReason')!r}), expected 'RUNNING'"
    )
    first = f"before-update-{uuid.uuid4().hex}"
    sqs.send_message(QueueUrl=src_url, MessageBody=first)
    got = _receive_until(ctx, a_url, first)
    assert got["Body"] == first, f"queue A body {got['Body']!r} != sent {first!r}"

    updated = pipes.update_pipe(Name=name, RoleArn=role_arn, Target=b_arn, TargetParameters=template)
    assert updated["DesiredState"] == "RUNNING", f"UpdatePipe echoed DesiredState {updated['DesiredState']!r}"
    desc = _wait_state(ctx, name, {"RUNNING", "STOPPED", "UPDATE_FAILED"})
    assert desc["CurrentState"] == "RUNNING", (
        f"after UpdatePipe the pipe settled in {desc['CurrentState']!r} ({desc.get('StateReason')!r})"
    )
    assert desc["Target"] == b_arn, "DescribePipe still reports the old Target after UpdatePipe named queue B"
    assert desc["Source"] == src_arn, "UpdatePipe changed the pipe's Source, which it did not name"

    second = f"after-update-{uuid.uuid4().hex}"
    sqs.send_message(QueueUrl=src_url, MessageBody=second)
    got = _receive_until(ctx, b_url, second)
    assert got["Body"] == second, f"queue B body {got['Body']!r} != sent {second!r}"
    stray = [m["Body"] for m in _receive_all(ctx, a_url, 15.0)]
    assert stray == [], f"the old target queue A still received {len(stray)} message(s) after the update: {stray!r}"

    _delete_pipe_and_wait(ctx, name)




def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) that ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_queue(ctx, prefix: str, attributes: dict | None = None) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    kwargs = {"QueueName": ctx.unique_name(prefix), "tags": dict(_RES_TAGS)}
    if attributes:
        kwargs["Attributes"] = attributes
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue(ctx, url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _delete_queue(ctx, url: str) -> None:
    try:
        ctx.client("sqs").delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"):
            raise


def _create_pipe_role(ctx, statements: list[dict]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipes-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "pipes.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _RES_TAGS.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="pipe-access",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="pipe-access"))
    # IAM propagation exposes no pollable condition; the bounded retry in
    # _create_pipe_with_retry rides it out on first use.
    return role_arn


def _sqs_pipe_statements(source_arns: list[str], target_arns: list[str]) -> list[dict]:
    return [
        {
            "Effect": "Allow",
            "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
            "Resource": source_arns,
        },
        {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arns},
    ]


def _create_pipe_with_retry(ctx, timeout_s: float = 90.0, **kwargs) -> dict:
    """CreatePipe, retrying only while the fresh execution role is still propagating."""
    pipes = ctx.client("pipes")
    left = ctx.time_left()
    if left is not None:
        timeout_s = max(1.0, min(timeout_s, left - 10.0))
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = pipes.create_pipe(**kwargs)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ValidationException", "AccessDeniedException") and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
    name = kwargs["Name"]
    ctx.on_cleanup(lambda: _delete_pipe_quiet(ctx, name))
    return resp


def _delete_pipe_quiet(ctx, name: str) -> None:
    """Backstop teardown: issue DeletePipe, riding out a transition in flight."""
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + 45.0
    while True:
        try:
            pipes.delete_pipe(Name=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code == "ConflictException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _delete_pipe_and_wait(ctx, name: str, timeout_s: float = 180.0) -> None:
    """Inline verified teardown: delete the pipe and poll until DescribePipe is NotFound."""
    pipes = ctx.client("pipes")
    _delete_pipe_quiet(ctx, name)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            pipes.describe_pipe(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(3)
    raise AssertionError(f"pipe {name} was still present {timeout_s:.0f}s after DeletePipe")


def _wait_state(ctx, name: str, states: set[str], timeout_s: float = 180.0) -> dict:
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = pipes.describe_pipe(Name=name)
        last = desc["CurrentState"]
        if last in states:
            return desc
        time.sleep(3)
    raise AssertionError(f"pipe {name} never reached {sorted(states)}; last CurrentState was {last!r}")


def _receive_all(ctx, url: str, window_s: float) -> list[dict]:
    """Drain every message visible on ``url`` for ``window_s`` seconds, deleting each."""
    sqs = ctx.client("sqs")
    out: list[dict] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5, MessageAttributeNames=["All"]
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
            out.append(msg)
    return out


def _receive_until(ctx, url: str, marker: str, timeout_s: float = 120.0) -> dict:
    """Poll ``url`` until a message whose body carries ``marker`` arrives; return it."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    seen: list[str] = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5, MessageAttributeNames=["All"]
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
            if marker in msg["Body"]:
                return msg
            seen.append(msg["Body"][:200])
    raise AssertionError(f"no message carrying {marker!r} reached the queue within {timeout_s:.0f}s; saw {seen!r}")



if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
