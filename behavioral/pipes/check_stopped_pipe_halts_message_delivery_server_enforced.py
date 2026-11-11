"""stopped-pipe-halts-message-delivery-server-enforced."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stopped-pipe-halts-message-delivery-server-enforced"
GROUP = "server-side"
SERVICES = ["pipes"]

_RES_TAGS = {"sim2real": CHECK}

# The longest an SQS ReceiveMessage long poll can stay outstanding (WaitTimeSeconds maximum).
_SQS_LONG_POLL_MAX_S = 20.0


@tags("axis:negative-delivery", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A STOPPED pipe truly halts polling: messages sit un-delivered until restarted."""
    pipes = ctx.client("pipes")
    sqs = ctx.client("sqs")

    source_url, source_arn = _create_queue(ctx, "sim2real-pipes-stop-src-")
    target_url, target_arn = _create_queue(ctx, "sim2real-pipes-stop-dst-")
    role_arn, role_name, policy_name = _create_pipe_role(ctx, [source_arn], [target_arn])
    # Cleanup runs LIFO: registering the role delete first means the policy delete (registered
    # second) runs first, so the role has no attached policy left when DeleteRole runs.
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    pipe_name = ctx.unique_name("sim2real-pipes-stop-")
    _create_pipe_with_retry(
        ctx,
        Name=pipe_name,
        Source=source_arn,
        Target=target_arn,
        RoleArn=role_arn,
        DesiredState="RUNNING",
        Tags=_RES_TAGS,
    )
    ctx.on_cleanup(lambda: _safe_delete_pipe(ctx, pipe_name))
    _wait_for_pipe_state(ctx, pipe_name, {"RUNNING"})

    pipes.stop_pipe(Name=pipe_name)
    _wait_for_pipe_state(ctx, pipe_name, {"STOPPED"})

    # CurrentState can flip to STOPPED while a long-poll receive the poller already had
    # outstanding against the source queue is still draining (up to one SQS long-poll max).
    # Hold across that window before sending the probe message, so the drain cannot be what
    # delivers it; a flap back to RUNNING during the hold is itself caught.
    _assert_state_holds(ctx, pipe_name, "STOPPED", hold_s=_SQS_LONG_POLL_MAX_S + 10.0, interval_s=5.0)

    marker = uuid.uuid4().hex
    sqs.send_message(QueueUrl=source_url, MessageBody=f"halted-{marker}")

    # While STOPPED the target is sampled across one SQS long-poll maximum, and every sample
    # re-reads CurrentState so a flap back to RUNNING is caught; the restart below is the contrast.
    stopped_deadline = time.monotonic() + _SQS_LONG_POLL_MAX_S
    while time.monotonic() < stopped_deadline:
        resp = sqs.receive_message(QueueUrl=target_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=target_url, ReceiptHandle=msg["ReceiptHandle"])
            assert marker not in msg["Body"], "message was delivered to target while pipe was STOPPED"
        current = pipes.describe_pipe(Name=pipe_name)["CurrentState"]
        assert current == "STOPPED", f"pipe {pipe_name} left STOPPED while the message was held (now {current!r})"

    attrs = sqs.get_queue_attributes(QueueUrl=source_url, AttributeNames=["ApproximateNumberOfMessages"])
    assert int(attrs["Attributes"]["ApproximateNumberOfMessages"]) >= 1, (
        "message disappeared from source queue even though the pipe was STOPPED"
    )

    # Positive control: restarting the SAME pipe now delivers the SAME message.
    pipes.start_pipe(Name=pipe_name)
    _wait_for_pipe_state(ctx, pipe_name, {"RUNNING"})

    delivered = None
    running_deadline = time.monotonic() + 90.0
    while time.monotonic() < running_deadline and delivered is None:
        resp = sqs.receive_message(QueueUrl=target_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=target_url, ReceiptHandle=msg["ReceiptHandle"])
            if marker in msg["Body"]:
                delivered = msg["Body"]

    assert delivered is not None, "pipe never delivered the message once restarted (positive control failed)"


def _create_queue(ctx, prefix: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(prefix), tags=dict(_RES_TAGS))["QueueUrl"]
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


def _safe_delete_pipe(ctx, name: str, timeout_s: float = 60.0) -> None:
    pipes = ctx.client("pipes")
    try:
        pipes.stop_pipe(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "ConflictException"):
            raise
    # DeletePipe can land while the pipe is still transitioning out of RUNNING from the
    # stop_pipe call just above; retry the conflict rather than letting it outrun us.
    deadline = time.monotonic() + timeout_s
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
        Tags=[{"Key": k, "Value": v} for k, v in _RES_TAGS.items()],
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
    left = ctx.time_left()
    if left is not None:
        timeout_s = max(1.0, min(timeout_s, left - 10.0))
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return pipes.create_pipe(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ValidationException", "AccessDeniedException"):
                last_exc = exc
                time.sleep(2)
                continue
            raise
    assert last_exc is not None, f"create_pipe retry loop for {kwargs.get('Name')!r} exited with no exception recorded"
    raise last_exc


def _assert_state_holds(ctx, name: str, expected_state: str, hold_s: float, interval_s: float) -> None:
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + hold_s
    while time.monotonic() < deadline:
        current = pipes.describe_pipe(Name=name)["CurrentState"]
        assert current == expected_state, (
            f"pipe {name} left {expected_state} during the settle window (now {current!r})"
        )
        time.sleep(interval_s)


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
