"""create-pipe-input-template-over-max-length-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-pipe-input-template-over-max-length-rejected"
GROUP = "validation"
SERVICES = ["iam", "pipes", "sqs"]

_RES_TAGS = {"sim2real": CHECK}
_MAX_LEN = 8192
_BASE = '{"v": ""}'


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePipe refuses a TargetParameters.InputTemplate one character over its 8192-character
    maximum with ValidationException, creating nothing; the same name then creates cleanly with
    a template at the limit, which is delivered unchanged."""
    sqs = ctx.client("sqs")
    pipes = ctx.client("pipes")
    src_url, src_arn = _create_queue(ctx, "sim2real-pipes-tmaxlen-src-")
    tgt_url, tgt_arn = _create_queue(ctx, "sim2real-pipes-tmaxlen-dst-")
    role_arn = _create_pipe_role(ctx, _sqs_pipe_statements([src_arn], [tgt_arn]))

    name = ctx.unique_name("sim2real-pipes-tmaxlen-")
    padding_too_long = "a" * (_MAX_LEN + 1 - len(_BASE))
    over_limit_template = '{"v": "' + padding_too_long + '"}'
    assert len(over_limit_template) == _MAX_LEN + 1, (
        f"test setup error: over_limit_template is {len(over_limit_template)} chars, want {_MAX_LEN + 1}"
    )

    over_max_length = (
        "ValidationException",
        f'[string "{over_limit_template}" is too long (length: {len(over_limit_template)}, '
        f"maximum allowed: {_MAX_LEN})]",
    )
    expect_error(
        lambda: pipes.create_pipe(
            Name=name,
            RoleArn=role_arn,
            Source=src_arn,
            SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
            Target=tgt_arn,
            TargetParameters={"InputTemplate": over_limit_template},
            DesiredState="RUNNING",
            Tags=_RES_TAGS,
        ),
        *over_max_length,
    )

    _assert_not_found(ctx, name)

    padding_at_limit = "a" * (_MAX_LEN - len(_BASE))
    at_limit_template = '{"v": "' + padding_at_limit + '"}'
    assert len(at_limit_template) == _MAX_LEN, (
        f"test setup error: at_limit_template is {len(at_limit_template)} chars, want {_MAX_LEN}"
    )

    _create_pipe_with_retry(
        ctx,
        Name=name,
        RoleArn=role_arn,
        Source=src_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        Target=tgt_arn,
        TargetParameters={"InputTemplate": at_limit_template},
        DesiredState="RUNNING",
        Tags=_RES_TAGS,
    )
    _wait_state(ctx, name, {"RUNNING"})

    sqs.send_message(QueueUrl=src_url, MessageBody=json.dumps({"ignored": "payload"}))
    msg = _receive_until(ctx, tgt_url, padding_at_limit)
    delivered = json.loads(msg["Body"])
    assert delivered == {"v": padding_at_limit}, (
        f"the at-limit template must render unchanged once CreatePipe accepts it; "
        f"got {delivered!r}"
    )

    _delete_pipe_and_wait(ctx, name)


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


def _assert_not_found(ctx, name: str) -> None:
    pipes = ctx.client("pipes")
    not_found = ("NotFoundException", f"Pipe {name} does not exist.")
    expect_error(lambda: pipes.describe_pipe(Name=name), *not_found)


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
    role_name = ctx.unique_name("sim2real-pipes-tmaxlen-role-")
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


def _receive_until(ctx, url: str, marker: str, timeout_s: float = 120.0) -> dict:
    """Poll `url` until a message whose body carries `marker` arrives; return it."""
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
