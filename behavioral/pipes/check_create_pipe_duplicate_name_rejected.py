"""create-pipe-duplicate-name-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-pipe-duplicate-name-rejected"
GROUP = "e2e"
SERVICES = ["pipes"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePipe with a Name that already exists is rejected and leaves the original untouched."""
    pipes = ctx.client("pipes")

    original_source_url, original_source_arn = _create_queue(ctx, "sim2real-pipes-dup-src-a-")
    other_source_url, other_source_arn = _create_queue(ctx, "sim2real-pipes-dup-src-b-")
    target_url, target_arn = _create_queue(ctx, "sim2real-pipes-dup-dst-")
    role_arn, role_name, policy_name = _create_pipe_role(
        ctx, [original_source_arn, other_source_arn], [target_arn]
    )

    def _delete_role() -> None:
        # The inline policy must go before the role itself.
        iam = ctx.client("iam")
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)

    pipe_name = ctx.unique_name("sim2real-pipes-dup-")
    _create_pipe_with_retry(
        ctx,
        Name=pipe_name,
        Source=original_source_arn,
        Target=target_arn,
        RoleArn=role_arn,
        DesiredState="STOPPED",
        Tags=_managed_tags(),
    )
    ctx.on_cleanup(lambda: _safe_delete_pipe(ctx, pipe_name))
    _wait_for_pipe_state(ctx, pipe_name, {"STOPPED"})

    # Break exactly one thing: try to create a SECOND pipe reusing the same Name
    # but pointing at a different source queue.
    code, message = _rejected_create_pipe_error(
        ctx,
        Name=pipe_name,
        Source=other_source_arn,
        Target=target_arn,
        RoleArn=role_arn,
        DesiredState="STOPPED",
    )
    assert code == "ConflictException", (
        f"CreatePipe reusing the existing name {pipe_name!r} must be rejected with "
        f"ConflictException, got {code!r}"
    )
    expected_message = f"Pipe {pipe_name} already exists."
    assert message == expected_message, (
        f"CreatePipe reusing the existing name {pipe_name!r}: expected message "
        f"{expected_message!r}, got {message!r}"
    )

    # Effect absent: the original pipe still points at its original source, not the
    # source from the rejected duplicate-name attempt.
    described = pipes.describe_pipe(Name=pipe_name)
    assert described["Source"] == original_source_arn, (
        f"the rejected duplicate-name CreatePipe changed pipe {pipe_name!r}'s Source: expected "
        f"the original {original_source_arn!r}, got {described['Source']!r}"
    )
    assert described["Source"] != other_source_arn, (
        f"pipe {pipe_name!r}'s Source must not have become the rejected attempt's source "
        f"{other_source_arn!r}"
    )

    # Positive control: CreatePipe works normally for a genuinely new, distinct name.
    control_name = ctx.unique_name("sim2real-pipes-dup-ctrl-")
    _create_pipe_with_retry(
        ctx,
        Name=control_name,
        Source=other_source_arn,
        Target=target_arn,
        RoleArn=role_arn,
        DesiredState="STOPPED",
        Tags=_managed_tags(),
    )
    ctx.on_cleanup(lambda: _safe_delete_pipe(ctx, control_name))
    control_described = _wait_for_pipe_state(ctx, control_name, {"STOPPED"})
    assert control_described["Source"] == other_source_arn, (
        f"control: a fresh pipe {control_name!r} using the same Source that was rejected under "
        f"the duplicate name must be created normally, got Source={control_described['Source']!r}"
    )


_MANAGED_TAG_KEY = "sim2real:managed"


def _managed_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true"}


def _create_queue(ctx, prefix: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(prefix), tags=_managed_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: _safe_delete_queue(ctx, url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _safe_delete_queue(ctx, url: str) -> None:
    try:
        ctx.client("sqs").delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
        ):
            raise


def _safe_delete_pipe(ctx, name: str) -> None:
    pipes = ctx.client("pipes")
    try:
        pipes.delete_pipe(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_pipe_role(ctx, source_arns: list[str], target_arns: list[str]) -> tuple[str, str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipes-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pipes.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _managed_tags().items()],
    )
    role_arn = role["Role"]["Arn"]
    policy_name = ctx.unique_name("sim2real-pipes-policy-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": source_arns,
            },
            {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arns},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    return role_arn, role_name, policy_name


def _create_pipe_with_retry(ctx, timeout_s: float = 60.0, **kwargs):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return pipes.create_pipe(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ValidationException", "AccessDeniedException"):
                last_exc = exc
                time.sleep(5)
                continue
            raise
    assert last_exc is not None, "create_pipe retry loop exited without ever calling create_pipe"
    raise last_exc


def _wait_for_pipe_state(ctx, name: str, target_states: set[str], timeout_s: float = 120.0, interval_s: float = 3.0):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = pipes.describe_pipe(Name=name)
        last = resp["CurrentState"]
        if last in target_states:
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"pipe {name} never reached {target_states}, last state was {last}")


def _rejected_create_pipe_error(ctx, **kwargs) -> tuple[str, str]:
    """create_pipe expecting a rejection; returns the AWS error code and message.

    Never returns a falsy sentinel: an ACCEPTED call is the strongest possible signal (the
    service took input real AWS refuses), so it raises rather than degrading into a code
    mismatch. The response is captured before the raise so the wrongly-created pipe still gets
    a teardown.
    """
    pipes = ctx.client("pipes")
    name = kwargs["Name"]
    try:
        resp = pipes.create_pipe(**kwargs)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    ctx.on_cleanup(lambda: _safe_delete_pipe(ctx, name))
    raise AssertionError(
        f"create_pipe({name!r}) with a duplicate Name was ACCEPTED where real AWS rejects it; "
        f"response {resp!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
