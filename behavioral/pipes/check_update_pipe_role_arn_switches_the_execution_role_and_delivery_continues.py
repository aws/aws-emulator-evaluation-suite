"""update-pipe-role-arn-switches-the-execution-role-and-delivery-continues."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-pipe-role-arn-switches-the-execution-role-and-delivery-continues"
GROUP = "lifecycle"
SERVICES = ["pipes"]

_RES_TAGS = {"sim2real": CHECK}


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdatePipe with a new RoleArn moves a running SQS-to-SQS pipe onto that role: DescribePipe
    reports it, and a record then reaches a queue only the new role may send to.
    """
    sqs = ctx.client("sqs")
    src_url, src_arn = _create_queue(ctx, "sim2real-pipes-rerole-src-")
    old_url, old_tgt = _create_queue(ctx, "sim2real-pipes-rerole-a-")
    new_url, new_tgt = _create_queue(ctx, "sim2real-pipes-rerole-b-")
    old_arn = _create_pipe_role(ctx, _sqs_pipe_statements([src_arn], [old_tgt]))
    new_arn = _create_pipe_role(ctx, _sqs_pipe_statements([src_arn], [new_tgt]))

    name = ctx.unique_name("sim2real-pipes-rerole-")
    template = {"InputTemplate": "<$.body>"}
    _create_pipe_with_retry(
        ctx, Name=name, RoleArn=old_arn, Source=src_arn, Target=old_tgt,
        TargetParameters=template, DesiredState="RUNNING", Tags=_RES_TAGS,
    )
    desc = _wait_state(ctx, name, {"RUNNING", "STOPPED", "CREATE_FAILED"})
    assert desc["CurrentState"] == "RUNNING", (
        f"pipe settled in {desc['CurrentState']!r} ({desc.get('StateReason')!r}), expected 'RUNNING'"
    )
    assert desc["RoleArn"] == old_arn, f"DescribePipe RoleArn {desc['RoleArn']!r} != created {old_arn!r}"
    first = f"before-update-{uuid.uuid4().hex}"
    sqs.send_message(QueueUrl=src_url, MessageBody=first)
    got = _receive_until(ctx, old_url, first)
    assert got["Body"] == first, f"queue A body {got['Body']!r} != sent {first!r}"

    # The old role may not send to queue B, so a record reaching B is delivered under the new role.
    updated = _update_pipe_with_retry(ctx, Name=name, RoleArn=new_arn, Target=new_tgt, TargetParameters=template)
    assert updated["DesiredState"] == "RUNNING", f"UpdatePipe echoed DesiredState {updated['DesiredState']!r}"
    desc = _wait_state(ctx, name, {"RUNNING", "STOPPED", "UPDATE_FAILED"})
    assert desc["CurrentState"] == "RUNNING", (
        f"after UpdatePipe the pipe settled in {desc['CurrentState']!r} ({desc.get('StateReason')!r})"
    )
    assert desc["RoleArn"] == new_arn, f"DescribePipe RoleArn {desc['RoleArn']!r} != updated {new_arn!r}"
    assert (desc["Source"], desc["Target"]) == (src_arn, new_tgt), (
        f"DescribePipe Source/Target after UpdatePipe: {desc['Source']!r}, {desc['Target']!r}"
    )

    second = f"after-update-{uuid.uuid4().hex}"
    sqs.send_message(QueueUrl=src_url, MessageBody=second)
    got = _receive_until(ctx, new_url, second)
    assert got["Body"] == second, f"queue B body {got['Body']!r} != sent {second!r}"

    _delete_pipe_and_wait(ctx, name)


# ===== self-contained helpers =====


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
    # IAM propagation exposes no pollable condition; the bounded retries in
    # _create_pipe_with_retry and _update_pipe_with_retry ride it out on first use.
    return role_arn


def _update_pipe_with_retry(ctx, timeout_s: float = 90.0, **kwargs) -> dict:
    """UpdatePipe, retrying only while the fresh execution role is still propagating."""
    pipes = ctx.client("pipes")
    left = ctx.time_left()
    if left is not None:
        timeout_s = max(1.0, min(timeout_s, left - 10.0))
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return pipes.update_pipe(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ValidationException", "AccessDeniedException") and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


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
