"""start-already-running-pipe-is-idempotent-noop."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-already-running-pipe-is-idempotent-noop"
GROUP = "state-machine"
SERVICES = ["pipes"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartPipe on an already-RUNNING pipe succeeds rather than raising ConflictException and
    the pipe settles back on RUNNING; a later StopPipe still works."""
    pipes = ctx.client("pipes")
    role_arn = _create_pipes_role(ctx)
    source_url, source_arn = _create_queue(ctx, "src")
    target_url, target_arn = _create_queue(ctx, "tgt")
    _grant_pipe_permissions(ctx, role_arn, source_arn, target_arn)

    name = ctx.unique_name("sim2real-pipes-startconf-")
    _create_pipe_with_retry(
        ctx,
        pipes,
        Name=name,
        Source=source_arn,
        Target=target_arn,
        RoleArn=role_arn,
        DesiredState="STOPPED",
    )
    ctx.on_cleanup(lambda: _delete_pipe_safely(pipes, name))

    _poll_until(
        lambda: pipes.describe_pipe(Name=name),
        lambda d: d["CurrentState"] == "STOPPED",
        timeout_s=180.0,
    )

    # Positive control: StartPipe on a STOPPED pipe succeeds and reaches RUNNING.
    pipes.start_pipe(Name=name)
    running = _poll_until(
        lambda: pipes.describe_pipe(Name=name),
        lambda d: d["CurrentState"] in ("RUNNING", "START_FAILED"),
        timeout_s=180.0,
    )
    assert running["CurrentState"] == "RUNNING", "positive control: StartPipe on STOPPED pipe must reach RUNNING"

    # Break exactly one thing: StartPipe again while already RUNNING. On real AWS this is
    # accepted (no ConflictException) as a redundant desired-state assignment; the pipe
    # may transiently re-enter STARTING but must settle back on RUNNING, never on STOPPED
    # or any *_FAILED state.
    redundant = pipes.start_pipe(Name=name)
    assert redundant["CurrentState"] in ("RUNNING", "STARTING"), (
        f"redundant StartPipe on an already-RUNNING pipe returned unexpected CurrentState "
        f"{redundant['CurrentState']!r}"
    )
    assert redundant["DesiredState"] == "RUNNING", (
        f"redundant StartPipe on an already-RUNNING pipe returned unexpected DesiredState "
        f"{redundant['DesiredState']!r}, expected 'RUNNING'"
    )

    after = _poll_until(
        lambda: pipes.describe_pipe(Name=name),
        lambda d: d["CurrentState"] in ("RUNNING", "START_FAILED"),
        timeout_s=180.0,
    )
    assert after["CurrentState"] == "RUNNING", (
        f"a redundant StartPipe on an already-RUNNING pipe must settle back on RUNNING, "
        f"got {after['CurrentState']!r}"
    )

    # Restore control: the pipe must not be left stuck by the idempotent no-op -- a
    # genuinely different, legitimate transition (StopPipe) must still work afterward.
    pipes.stop_pipe(Name=name)
    stopped = _poll_until(
        lambda: pipes.describe_pipe(Name=name),
        lambda d: d["CurrentState"] in ("STOPPED", "STOP_FAILED"),
        timeout_s=180.0,
    )
    assert stopped["CurrentState"] == "STOPPED", (
        f"StopPipe after the redundant StartPipe no-op must still settle on STOPPED, "
        f"got {stopped['CurrentState']!r}"
    )


# ===== helpers =====

def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _create_queue(ctx, suffix: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(f"sim2real-pipes-{suffix}-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_pipes_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipes-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "pipes.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _grant_pipe_permissions(ctx, role_arn: str, source_arn: str, target_arn: str) -> None:
    iam = ctx.client("iam")
    role_name = role_arn.split("/")[-1]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": source_arn,
            },
            {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arn},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(policy))


def _create_pipe_with_retry(ctx, pipes, **kwargs: Any):
    """CreatePipe, retrying for up to 60 s while the fresh execution role is still propagating."""
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else max(1.0, min(60.0, left - 10.0)))
    while True:
        try:
            return pipes.create_pipe(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ValidationException", "NotFoundException") and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


def _delete_pipe_safely(pipes, name: str) -> None:
    for _ in range(15):
        try:
            pipes.delete_pipe(Name=name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code == "ConflictException":
                time.sleep(5)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
