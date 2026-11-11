"""update-pipe-while-running-preserves-desired-state."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-pipe-while-running-preserves-desired-state"
GROUP = "state-machine"
SERVICES = ["pipes"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePipe on a RUNNING pipe changes configuration and settles back at RUNNING (DesiredState
    is never dropped to STOPPED as a side effect of the update)."""
    pipes = ctx.client("pipes")
    res_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-pipes-update"}
    role_arn = _create_pipes_role(ctx, res_tags)
    source_url, source_arn = _create_queue(ctx, "src", res_tags)
    target_url, target_arn = _create_queue(ctx, "tgt", res_tags)
    _grant_pipe_permissions(ctx, role_arn, source_arn, target_arn)

    name = ctx.unique_name("sim2real-pipes-update-")
    _create_pipe_with_retry(
        ctx,
        pipes,
        Name=name,
        Source=source_arn,
        Target=target_arn,
        RoleArn=role_arn,
        Description="before-update",
        DesiredState="RUNNING",
        Tags=res_tags,
    )
    ctx.on_cleanup(lambda: _delete_pipe_safely(pipes, name))

    running = _poll_until(
        lambda: pipes.describe_pipe(Name=name),
        lambda d: d["CurrentState"] in ("RUNNING", "CREATE_FAILED"),
        timeout_s=180.0,
    )
    assert running["CurrentState"] == "RUNNING", "setup: pipe must reach RUNNING before update"

    update_resp = pipes.update_pipe(
        Name=name,
        RoleArn=role_arn,
        Description="after-update",
    )
    assert update_resp["DesiredState"] == "RUNNING", "UpdatePipe must not change DesiredState away from RUNNING"

    settled = _poll_until(
        lambda: pipes.describe_pipe(Name=name),
        lambda d: d["CurrentState"] in ("RUNNING", "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED"),
        timeout_s=180.0,
    )
    assert settled["CurrentState"] == "RUNNING", (
        f"pipe must settle back at RUNNING after an update, got {settled['CurrentState']!r} "
        f"reason={settled.get('StateReason')!r}"
    )
    assert settled["DesiredState"] == "RUNNING", (
        f"DesiredState must remain RUNNING after settling, got {settled['DesiredState']!r}"
    )
    assert settled["Description"] == "after-update", "the configuration change itself must have taken effect"


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


def _create_queue(ctx, suffix: str, res_tags: dict[str, str]) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-pipes-{suffix}-"), tags=res_tags
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_pipes_role(ctx, res_tags: dict[str, str]) -> str:
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
    role_tags = [{"Key": k, "Value": v} for k, v in res_tags.items()]
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust, Tags=role_tags
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
