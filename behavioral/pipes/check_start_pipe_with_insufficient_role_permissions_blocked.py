"""start-pipe-with-insufficient-role-permissions-blocked."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-pipe-with-insufficient-role-permissions-blocked"
GROUP = "overly-permissive"
SERVICES = ["pipes"]

_RES_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pipe whose execution role cannot read its source must fail creation validation (CREATE_FAILED),
    never reach a healthy RUNNING state, and must not consume the source message — proving EventBridge
    Pipes actually enforces (rather than rubber-stamps) the execution-role IAM permissions on the source.
    """
    pipes = ctx.client("pipes")

    # ---- Negative subject: role with a valid trust policy but zero grants on the source. ----
    bad_role_arn = _create_pipes_role(ctx)
    bad_source_url, bad_source_arn = _create_queue(ctx, "bad-src")
    bad_target_url, bad_target_arn = _create_queue(ctx, "bad-tgt")
    sentinel_body = ctx.unique_name("sim2real-pipes-sentinel-")
    ctx.client("sqs").send_message(QueueUrl=bad_source_url, MessageBody=sentinel_body)

    bad_name = ctx.unique_name("sim2real-pipes-badrole-")
    _create_pipe_with_retry(
        ctx,
        pipes,
        Name=bad_name,
        Source=bad_source_arn,
        Target=bad_target_arn,
        RoleArn=bad_role_arn,
        DesiredState="RUNNING",
        Tags=_RES_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_pipe_safely(pipes, bad_name))

    bad_final = _poll_until(
        lambda: pipes.describe_pipe(Name=bad_name),
        lambda d: d["CurrentState"] not in ("CREATING",),
        timeout_s=200.0,
    )
    assert bad_final["CurrentState"] == "CREATE_FAILED", (
        f"a role with no source-read permission must not settle in a healthy state, "
        f"got {bad_final['CurrentState']!r} reason={bad_final.get('StateReason')!r}"
    )
    assert bad_final.get("StateReason"), "CREATE_FAILED must carry a non-empty StateReason"

    # Effect absent: the pipe never started polling, so the sentinel message is untouched.
    remaining = ctx.client("sqs").receive_message(
        QueueUrl=bad_source_url, MaxNumberOfMessages=1, WaitTimeSeconds=2
    )
    assert remaining.get("Messages"), "sentinel message must still be on the source queue (never consumed)"
    assert remaining["Messages"][0]["Body"] == sentinel_body, (
        f"sentinel body must be untouched, expected {sentinel_body!r}, "
        f"got {remaining['Messages'][0]['Body']!r}"
    )

    # ---- Positive control in the same file: identical setup, but with a correctly-permissioned role. ----
    good_role_arn = _create_pipes_role(ctx)
    good_source_url, good_source_arn = _create_queue(ctx, "good-src")
    good_target_url, good_target_arn = _create_queue(ctx, "good-tgt")
    _grant_pipe_permissions(ctx, good_role_arn, good_source_arn, good_target_arn)

    good_name = ctx.unique_name("sim2real-pipes-goodrole-")
    _create_pipe_with_retry(
        ctx,
        pipes,
        Name=good_name,
        Source=good_source_arn,
        Target=good_target_arn,
        RoleArn=good_role_arn,
        DesiredState="RUNNING",
        Tags=_RES_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_pipe_safely(pipes, good_name))

    good_final = _poll_until(
        lambda: pipes.describe_pipe(Name=good_name),
        lambda d: d["CurrentState"] in ("RUNNING", "CREATE_FAILED"),
        timeout_s=200.0,
    )
    assert good_final["CurrentState"] == "RUNNING", (
        f"positive control: a properly-permissioned role must reach RUNNING, "
        f"got {good_final['CurrentState']!r} reason={good_final.get('StateReason')!r}"
    )

    payload = ctx.unique_name("sim2real-pipes-payload-")
    ctx.client("sqs").send_message(QueueUrl=good_source_url, MessageBody=payload)
    delivered = _poll_until(
        lambda: ctx.client("sqs").receive_message(
            QueueUrl=good_target_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
        ),
        lambda r: bool(r.get("Messages")),
        timeout_s=90.0,
        interval_s=5.0,
    )
    assert payload in delivered["Messages"][0]["Body"], "positive control: message must flow end-to-end"


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
        QueueName=ctx.unique_name(f"sim2real-pipes-{suffix}-"), tags=_RES_TAGS
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
        Tags=[{"Key": k, "Value": v} for k, v in _RES_TAGS.items()],
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
