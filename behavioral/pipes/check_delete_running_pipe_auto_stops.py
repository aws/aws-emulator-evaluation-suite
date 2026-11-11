"""delete-running-pipe-auto-stops."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-running-pipe-auto-stops"
GROUP = "state-machine"
SERVICES = ["pipes"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeletePipe on a RUNNING pipe is accepted directly (no prior StopPipe needed) and fully removes it."""
    pipes = ctx.client("pipes")
    role_arn = _create_pipes_role(ctx)
    source_url, source_arn = _create_queue(ctx, "src")
    target_url, target_arn = _create_queue(ctx, "tgt")
    _grant_pipe_permissions(ctx, role_arn, source_arn, target_arn)

    name = ctx.unique_name("sim2real-pipes-delrun-")
    _create_pipe_with_retry(
        ctx,
        pipes,
        Name=name,
        Source=source_arn,
        Target=target_arn,
        RoleArn=role_arn,
        DesiredState="RUNNING",
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-pipes-delrun"},
    )

    running = _poll_until(
        lambda: pipes.describe_pipe(Name=name),
        lambda d: d["CurrentState"] in ("RUNNING", "CREATE_FAILED"),
        timeout_s=180.0,
    )
    assert running["CurrentState"] == "RUNNING", "setup: pipe must reach RUNNING before delete"

    # Break exactly one thing under test: delete a RUNNING pipe without an explicit StopPipe first.
    delete_resp = pipes.delete_pipe(Name=name)
    assert delete_resp["CurrentState"] in ("DELETING", "DELETE_FAILED"), (
        f"DeletePipe on a RUNNING pipe must be accepted directly, got {delete_resp['CurrentState']!r}"
    )
    assert delete_resp["CurrentState"] != "DELETE_FAILED", (
        f"DeletePipe on a RUNNING pipe must not fail, got CurrentState={delete_resp['CurrentState']!r}"
    )

    def _describe_or_gone():
        try:
            return pipes.describe_pipe(Name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return "GONE"
            raise

    final = _poll_until(_describe_or_gone, lambda v: v == "GONE", timeout_s=180.0)
    assert final == "GONE", "pipe must be fully removed after DeletePipe on a RUNNING pipe"

    # Gone means unusable too: a second DeletePipe on the now-deleted name must fail
    # with the specific not-found code, not silently succeed or raise something else.
    try:
        pipes.delete_pipe(Name=name)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")
    else:
        raise AssertionError("DeletePipe on an already-deleted pipe must fail, but it succeeded")
    assert code == "NotFoundException", (
        f"DeletePipe on an already-deleted pipe must fail with NotFoundException, got {code!r}"
    )
    expected_message = f"Pipe {name} does not exist."
    assert message == expected_message, (
        f"DeletePipe on an already-deleted pipe: expected message {expected_message!r}, got {message!r}"
    )


# ===== helpers =====

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
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-pipes-{suffix}-"),
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-pipes-delrun"},
    )["QueueUrl"]
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-pipes-delrun"}],
    )["Role"]["Arn"]

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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
