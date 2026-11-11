"""create-pipe-malformed-input-template-json-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-pipe-malformed-input-template-json-rejected"
GROUP = "validation"
SERVICES = ["pipes"]

_RES_TAGS = {"sim2real": CHECK}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """CreatePipe refuses an InputTemplate whose literal JSON is malformed with
    ValidationException and creates nothing, while the same shape with valid JSON is accepted."""
    _, src_arn = _create_queue(ctx, "sim2real-pipes-badtpl-src-")
    _, tgt_arn = _create_queue(ctx, "sim2real-pipes-badtpl-dst-")
    role_arn = _create_pipe_role(ctx, [src_arn], [tgt_arn])

    # Positive control first, so the execution role is assumable before the refusal is asserted.
    good_name = ctx.unique_name("sim2real-pipes-badtpl-good-")
    _create_pipe_with_retry(
        ctx,
        Name=good_name,
        RoleArn=role_arn,
        Source=src_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        Target=tgt_arn,
        TargetParameters={"InputTemplate": '{"ok": "<$.body.marker>"}'},
        DesiredState="STOPPED",
        Tags=_RES_TAGS,
    )
    _wait_state(ctx, good_name, {"STOPPED"})
    described = ctx.client("pipes").describe_pipe(Name=good_name)
    assert described["TargetParameters"]["InputTemplate"] == '{"ok": "<$.body.marker>"}', (
        f"control leg: the well-formed InputTemplate must be accepted and echoed, got "
        f"{described['TargetParameters']!r}"
    )

    pipes = ctx.client("pipes")
    rejected_name = ctx.unique_name("sim2real-pipes-badtpl-bad-")
    code, message = _error(
        lambda: pipes.create_pipe(
            Name=rejected_name,
            RoleArn=role_arn,
            Source=src_arn,
            SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
            Target=tgt_arn,
            TargetParameters={"InputTemplate": '{"broken": <$.body.marker'},
            DesiredState="RUNNING",
            Tags=_RES_TAGS,
        )
    )
    assert code == "ValidationException", (
        f"a syntactically invalid InputTemplate must be refused with ValidationException, got "
        f"{code!r} ({message!r})"
    )
    assert message == (
        '{"ValidationErrorFields":[{"Name":"InputTemplate",'
        '"Message":"Invalid JSON format for Input Template."}]}'
    ), f"unexpected refusal message for a malformed InputTemplate: {message!r}"
    assert rejected_name not in _pipe_names(ctx, rejected_name), (
        f"the refused pipe {rejected_name!r} must not appear in list_pipes"
    )


# ===== helpers (self-contained) =====


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) that `fn` raises. An unexpected success raises too."""
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


def _create_pipe_role(ctx, source_arns: list[str], target_arns: list[str]) -> str:
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
    statements = [
        {
            "Effect": "Allow",
            "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
            "Resource": source_arns,
        },
        {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arns},
    ]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="pipe-access",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="pipe-access"))
    return role_arn


def _budget_s(ctx, cap_s):
    """A wait's timeout, bounded by the runner's remaining time so the wait fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _create_pipe_with_retry(ctx, timeout_s: float = 90.0, **kwargs) -> dict:
    """CreatePipe, retrying only while the fresh execution role is not yet assumable by Pipes."""
    pipes = ctx.client("pipes")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = pipes.create_pipe(**kwargs)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            role_not_ready = code == "AccessDeniedException" or (
                code == "ValidationException"
                and ("cannot be assumed" in msg or "iam:PassRole" in msg)
            )
            if not role_not_ready:
                raise
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"CreatePipe was refused for its execution role for {timeout_s:.0f}s: {exc}"
                ) from exc
            time.sleep(2)
    name = kwargs["Name"]
    ctx.on_cleanup(lambda: _delete_pipe_quiet(ctx, name))
    return resp


def _delete_pipe_quiet(ctx, name: str) -> None:
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


def _wait_state(ctx, name: str, states: set[str], timeout_s: float = 180.0) -> dict:
    pipes = ctx.client("pipes")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = pipes.describe_pipe(Name=name)
        last = desc["CurrentState"]
        if last in states:
            return desc
        time.sleep(3)
    raise TimeoutError(f"pipe {name} never reached {sorted(states)}; last CurrentState was {last!r}")


def _pipe_names(ctx, name_prefix: str) -> set[str]:
    pipes = ctx.client("pipes")
    names: set[str] = set()
    token = None
    while True:
        kwargs = {"NamePrefix": name_prefix}
        if token:
            kwargs["NextToken"] = token
        resp = pipes.list_pipes(**kwargs)
        names.update(p["Name"] for p in resp.get("Pipes", []))
        token = resp.get("NextToken")
        if not token:
            return names


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
