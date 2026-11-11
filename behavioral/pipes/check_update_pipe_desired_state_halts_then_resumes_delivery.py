"""update-pipe-desired-state-halts-then-resumes-delivery."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-pipe-desired-state-halts-then-resumes-delivery"
GROUP = "lifecycle"
SERVICES = ["pipes"]

_RES_TAGS = {"sim2real": CHECK}


@tags("axis:negative-delivery", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdatePipe DesiredState=STOPPED withholds a source message (absent from the target, still
    counted on the source) and DesiredState=RUNNING then delivers it, as IaC tools toggle pipes
    via UpdatePipe rather than StopPipe/StartPipe."""
    sqs = ctx.client("sqs")
    pipes = ctx.client("pipes")
    src_url, src_arn = _create_queue(ctx, "sim2real-pipes-upds-src-")
    tgt_url, tgt_arn = _create_queue(ctx, "sim2real-pipes-upds-dst-")
    role_arn = _create_pipe_role(ctx, _sqs_pipe_statements([src_arn], [tgt_arn]))

    name = ctx.unique_name("sim2real-pipes-upds-")
    _create_pipe_with_retry(
        ctx,
        Name=name,
        RoleArn=role_arn,
        Source=src_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        Target=tgt_arn,
        TargetParameters={"InputTemplate": "<$.body>"},
        DesiredState="RUNNING",
        Tags=_RES_TAGS,
    )
    _wait_state(ctx, name, {"RUNNING"}, timeout_s=_budget_s(ctx, 180.0))

    # Positive control: the running pipe delivers.
    control = f"control-{uuid.uuid4().hex}"
    sqs.send_message(QueueUrl=src_url, MessageBody=control)
    got = _receive_until(ctx, tgt_url, control, timeout_s=_budget_s(ctx, 120.0))
    assert got["Body"] == control, f"control delivery body {got['Body']!r} != {control!r}"

    pipes.update_pipe(Name=name, RoleArn=role_arn, DesiredState="STOPPED")
    desc = _wait_state(ctx, name, {"STOPPED"}, timeout_s=_budget_s(ctx, 180.0))
    assert desc["DesiredState"] == "STOPPED", f"DesiredState after the update was {desc['DesiredState']!r}"
    # CurrentState can read STOPPED while the poller's outstanding SQS long polls (up to 20 s)
    # are still draining, so hold across that window, re-checking that the state stays put.
    _hold_state(ctx, name, "STOPPED", hold_s=40.0)

    held = f"held-{uuid.uuid4().hex}"
    sqs.send_message(QueueUrl=src_url, MessageBody=held)
    leaked = [m["Body"] for m in _receive_all(ctx, tgt_url, window_s=45.0)]
    assert held not in leaked, "a message sent after UpdatePipe(DesiredState=STOPPED) settled was delivered"
    visible = _wait_visible(ctx, src_url, expected=1, timeout_s=_budget_s(ctx, 90.0))
    if visible != 1 and _budget_spent(ctx):
        raise TimeoutError("source queue withheld-message count: the run budget ended first; not graded")
    assert visible == 1, f"source queue should still hold the withheld message, ApproximateNumberOfMessages={visible}"

    pipes.update_pipe(Name=name, RoleArn=role_arn, DesiredState="RUNNING")
    desc = _wait_state(ctx, name, {"RUNNING"}, timeout_s=_budget_s(ctx, 180.0))
    assert desc["DesiredState"] == "RUNNING", f"DesiredState after the resume was {desc['DesiredState']!r}"
    got = _receive_until(ctx, tgt_url, held, timeout_s=_budget_s(ctx, 120.0))
    assert got["Body"] == held, f"resumed delivery body {got['Body']!r} != {held!r}"

    _delete_pipe_and_wait(ctx, name)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _hold_state(ctx, name: str, state: str, hold_s: float) -> None:
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + hold_s
    while time.monotonic() < deadline:
        current = pipes.describe_pipe(Name=name)["CurrentState"]
        assert current == state, f"pipe {name} left {state!r} for {current!r} while it should hold"
        time.sleep(2)


def _wait_visible(ctx, url: str, expected: int, timeout_s: float) -> int:
    """ApproximateNumberOfMessages is eventually consistent: poll until it reads ``expected``."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    value = -1
    while time.monotonic() < deadline:
        attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"])
        value = int(attrs["Attributes"]["ApproximateNumberOfMessages"])
        if value == expected:
            return value
        time.sleep(1)
    return value


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
    # _create_pipe_with_retry is what makes first use correct.
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
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while True:
        try:
            resp = pipes.create_pipe(**kwargs)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ValidationException", "AccessDeniedException") and time.monotonic() < deadline:
                time.sleep(2)
                continue
            if code in ("ValidationException", "AccessDeniedException") and _budget_spent(ctx):
                raise TimeoutError(
                    f"CreatePipe {kwargs['Name']} role propagation: the run budget ended first; not graded"
                ) from exc
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
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            pipes.describe_pipe(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"pipe {name} deleted: the run budget ended first; not graded")
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
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"pipe {name} {sorted(states)}: the run budget ended first; not graded")
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
    if _budget_spent(ctx):
        raise TimeoutError(f"message carrying {marker!r}: the run budget ended first; not graded")
    raise AssertionError(f"no message carrying {marker!r} reached the queue within {timeout_s:.0f}s; saw {seen!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
