"""pipe-batching-window-delays-delivery."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipe-batching-window-delays-delivery"
GROUP = "visibility-timeout-ttl"
SERVICES = ["pipes"]


# timing:real-time — buffer: 25 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-batching-concurrency.html
@tags("axis:negative-delivery", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A pipe configured with a MaximumBatchingWindowInSeconds withholds
    delivery of a single below-threshold message until the window elapses."""
    source_url, source_arn = _create_queue(ctx)
    target_url, target_arn = _create_queue(ctx)
    role_arn = _create_pipe_role(ctx, source_arn, target_arn)

    # MaximumBatchingWindowInSeconds accepts 0 to 300; 25 s leaves a 10 s early-absence leg.
    batching_window_s = 25
    name = ctx.unique_name("sim2real-pipe-batch-")
    _create_pipe(
        ctx,
        name,
        source_arn=source_arn,
        target_arn=target_arn,
        role_arn=role_arn,
        source_parameters={
            "SqsQueueParameters": {
                "BatchSize": 10,  # well above the 1 message we send
                "MaximumBatchingWindowInSeconds": batching_window_s,
            }
        },
        target_parameters={"InputTemplate": "<$.body>"},
    )
    desc = _wait_pipe_state(ctx, name, {"RUNNING"}, timeout_s=90.0)
    assert desc["Source"] == source_arn, f"pipe {name} reports Source {desc['Source']!r}, expected {source_arn!r}"

    sqs = ctx.client("sqs")
    body = f"batch-window-payload-{uuid.uuid4()}"
    send_time = time.monotonic()
    sqs.send_message(QueueUrl=source_url, MessageBody=body)

    # Well below the batching window: message must NOT have arrived yet. The absence
    # poll is bounded by the send time, so it ends at least 15s inside the window (one
    # receive long-poll is 5s) however slowly the calls above returned.
    early_budget_s = min(20.0, batching_window_s - 15.0 - (time.monotonic() - send_time))
    early = _poll_for_message_body(ctx, target_url, timeout_s=early_budget_s)
    assert early is None, f"message delivered before batching window elapsed: {early!r}"
    early_elapsed = time.monotonic() - send_time
    # elapsed-bound: the absence leg is only meaningful inside the configured batching window.
    assert early_elapsed < batching_window_s, (
        f"the absence check itself ran {early_elapsed:.1f}s, at or past the "
        f"{batching_window_s}s batching window it is meant to be well inside of"
    )

    # Poll well past the window for the eventual, batch-flushed delivery. This
    # must not fire early: a target that flushes at, say, half the configured
    # window would slip past the `early` check above (which only covers the
    # first 20s) if its arrival time were not itself bounded below.
    remaining = batching_window_s + 150.0 - (time.monotonic() - send_time)
    late = _poll_for_message_body(ctx, target_url, timeout_s=max(remaining, 30.0))
    late_elapsed = time.monotonic() - send_time
    assert late == body, f"expected {body!r} after batching window elapsed, got {late!r}"
    assert late_elapsed >= batching_window_s - 5, (
        f"message delivered after only {late_elapsed:.1f}s, before the "
        f"{batching_window_s}s configured batching window elapsed"
    )


# ===== helpers =====

_TERMINAL_FAILURE_STATES = {
    "CREATE_FAILED",
    "START_FAILED",
    "UPDATE_FAILED",
    "DELETE_FAILED",
    "CREATE_ROLLBACK_FAILED",
    "DELETE_ROLLBACK_FAILED",
    "UPDATE_ROLLBACK_FAILED",
}

_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pipes.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _create_queue(ctx, fifo=False):
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-pipe-q-")
    kwargs = {"QueueName": f"{name}.fifo" if fifo else name}
    if fifo:
        kwargs["Attributes"] = {"FifoQueue": "true", "ContentBasedDeduplication": "true"}
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_pipe_role(ctx, source_arn, target_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipe-role-")
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY)["Role"]
    policy_name = "pipe-access"
    policy_doc = json.dumps(
        {
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
    )
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_doc)

    def _cleanup():
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_pipe(
    ctx,
    name,
    source_arn,
    target_arn,
    role_arn,
    source_parameters=None,
    target_parameters=None,
    desired_state="RUNNING",
    extra_props=None,
):
    pipes = ctx.client("pipes")
    kwargs = {
        "Name": name,
        "Source": source_arn,
        "Target": target_arn,
        "RoleArn": role_arn,
        "DesiredState": desired_state,
    }
    if source_parameters:
        kwargs["SourceParameters"] = source_parameters
    if target_parameters:
        kwargs["TargetParameters"] = target_parameters
    if extra_props:
        kwargs.update(extra_props)

    deadline = time.monotonic() + 60.0
    resp = None
    while resp is None:
        try:
            resp = pipes.create_pipe(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ValidationException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise

    def _cleanup():
        try:
            desc = pipes.describe_pipe(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if desc["CurrentState"] not in ("STOPPED", "CREATE_FAILED", "STOP_FAILED", "START_FAILED"):
            if desc["CurrentState"] != "STOPPING":
                pipes.stop_pipe(Name=name)
            _wait_pipe_state(ctx, name, {"STOPPED", "STOP_FAILED"}, timeout_s=120.0)
        pipes.delete_pipe(Name=name)
        _wait_pipe_deleted(ctx, name, timeout_s=120.0)

    ctx.on_cleanup(_cleanup)
    return resp


def _wait_pipe_state(ctx, name, states, timeout_s=90.0, interval_s=4.0):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = pipes.describe_pipe(Name=name)
        last = desc["CurrentState"]
        if last in states:
            return desc
        if last in _TERMINAL_FAILURE_STATES:
            raise AssertionError(f"pipe {name} entered failure state {last}: {desc.get('StateReason')}")
        time.sleep(interval_s)
    raise AssertionError(f"pipe {name} did not reach {states} within {timeout_s}s (last={last})")


def _wait_pipe_deleted(ctx, name, timeout_s=60.0):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            pipes.describe_pipe(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(3.0)
    raise AssertionError(f"pipe {name} was not deleted within {timeout_s}s")


def _poll_for_message_body(ctx, queue_url, timeout_s=60.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            return msgs[0]["Body"]
        time.sleep(1.0)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
