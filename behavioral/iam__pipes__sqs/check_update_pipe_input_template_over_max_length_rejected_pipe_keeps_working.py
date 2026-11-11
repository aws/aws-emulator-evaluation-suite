"""update-pipe-input-template-over-max-length-rejected-pipe-keeps-working."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-pipe-input-template-over-max-length-rejected-pipe-keeps-working"
GROUP = "rejection"
SERVICES = ["iam", "pipes", "sqs"]

_MAX_LEN = 8192
_BASE = '{"m": "<$.body.marker>"}'


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:data-plane",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """UpdatePipe refuses a TargetParameters.InputTemplate one character over its 8192-character
    maximum with ValidationException, leaving a RUNNING pipe's prior template and delivery
    untouched."""
    sqs = ctx.client("sqs")
    pipes = ctx.client("pipes")
    source = _create_queue(ctx)
    target = _create_queue(ctx)
    role = _create_pipe_role(ctx, source["arn"], target["arn"])

    name = _create_pipe(
        ctx, source=source["arn"], target=target["arn"], role_arn=role["arn"],
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        TargetParameters={"InputTemplate": _BASE},
    )

    marker_before = _xname(ctx, "before")
    sqs.send_message(QueueUrl=source["url"], MessageBody=json.dumps({"marker": marker_before}))
    delivered_before = _wait_for_messages(ctx, target["url"], expected_count=1, timeout_s=120)[0]["body"]
    assert delivered_before == {"m": marker_before}, (
        f"baseline delivery with the original template must render the marker; got {delivered_before!r}"
    )

    too_long = '{"m": "' + "a" * (_MAX_LEN + 1 - len('{"m": ""}')) + '"}'
    assert len(too_long) == _MAX_LEN + 1, f"test setup error: too_long is {len(too_long)} chars"

    over_max_length = (
        "ValidationException",
        f'[string "{too_long}" is too long (length: {len(too_long)}, maximum allowed: {_MAX_LEN})]',
    )
    expect_error(
        lambda: pipes.update_pipe(
            Name=name, RoleArn=role["arn"], TargetParameters={"InputTemplate": too_long}
        ),
        *over_max_length,
    )

    desc = pipes.describe_pipe(Name=name)
    assert desc["TargetParameters"]["InputTemplate"] == _BASE, (
        f"a refused UpdatePipe must leave the prior InputTemplate untouched; describe_pipe shows "
        f"{desc['TargetParameters']['InputTemplate']!r}, expected {_BASE!r}"
    )
    assert desc["CurrentState"] == "RUNNING", f"expected the pipe to stay RUNNING, got {desc['CurrentState']!r}"

    marker_after = _xname(ctx, "after")
    sqs.send_message(QueueUrl=source["url"], MessageBody=json.dumps({"marker": marker_after}))
    delivered_after = _wait_for_messages(ctx, target["url"], expected_count=1, timeout_s=120)[0]["body"]
    assert delivered_after == {"m": marker_after}, (
        f"delivery with the original template must continue unaffected after the refused update; "
        f"got {delivered_after!r}"
    )


# ===== helpers (self-contained) =====


def expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn()`` raises exactly ``(code, message)``. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err.get("Code", ""), err.get("Message", ""))
        assert got == (code, message), f"got {got!r}, expected {(code, message)!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xname(ctx: Any, kind: str) -> str:
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Path="/sim2real/",
        Tags=[{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()],
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
