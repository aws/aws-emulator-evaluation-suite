"""concurrent-update-pipe-no-corruption."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-update-pipe-no-corruption"
GROUP = "concurrency"
SERVICES = ["pipes"]

_RES_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-pipes"}
_TAGS = [{"Key": k, "Value": v} for k, v in _RES_TAGS.items()]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdatePipe calls with different SourceParameters resolve to
    exactly one of the two submitted configurations -- never a hybrid/merged one."""
    pipes = ctx.client("pipes")
    sqs = ctx.client("sqs")

    src_url, src_arn = _create_queue(ctx, sqs, ctx.unique_name("sim2real-pipes-usrc-"))
    tgt_url, tgt_arn = _create_queue(ctx, sqs, ctx.unique_name("sim2real-pipes-utgt-"))

    role_arn = _create_pipes_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": src_arn,
            },
            {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": tgt_arn},
        ],
    )

    name = ctx.unique_name("sim2real-pipes-concupd-")
    _create_pipe_resilient(
        ctx,
        pipes,
        Name=name,
        Source=src_arn,
        Target=tgt_arn,
        RoleArn=role_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 2, "MaximumBatchingWindowInSeconds": 0}},
        Tags=_RES_TAGS,
    )
    ctx.on_cleanup(lambda: _stop_and_delete_pipe(pipes, name))
    _wait_for_pipe_state(pipes, name, {"RUNNING"}, timeout_s=180)

    config_a = {"BatchSize": 3, "MaximumBatchingWindowInSeconds": 11}
    config_b = {"BatchSize": 9, "MaximumBatchingWindowInSeconds": 47}

    barrier = threading.Barrier(2)

    def _update(cfg):
        barrier.wait()
        try:
            pipes.update_pipe(
                Name=name,
                RoleArn=role_arn,
                Target=tgt_arn,
                DesiredState="RUNNING",
                SourceParameters={"SqsQueueParameters": cfg},
            )
            return ("ok", None, None)
        except ClientError as e:
            return ("err", e.response["Error"]["Code"], e.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_update, config_a)
        fut_b = pool.submit(_update, config_b)
        results = [fut_a.result(), fut_b.result()]

    successes = [r for r in results if r[0] == "ok"]
    assert len(successes) >= 1, f"expected at least one UpdatePipe to succeed, got {results}"
    expected_msg = f"Pipe {name} is updating concurrently."
    for outcome, code, message in results:
        if outcome == "err":
            assert code == "ConflictException", f"unexpected UpdatePipe failure code {code}"
            assert message == expected_msg, f"expected UpdatePipe refusal {expected_msg!r}, got {message!r}"

    desc = _wait_for_pipe_state(pipes, name, {"RUNNING"}, timeout_s=180)
    final = desc["SourceParameters"]["SqsQueueParameters"]
    final_pair = (final["BatchSize"], final["MaximumBatchingWindowInSeconds"])
    valid_pairs = {
        (config_a["BatchSize"], config_a["MaximumBatchingWindowInSeconds"]),
        (config_b["BatchSize"], config_b["MaximumBatchingWindowInSeconds"]),
    }
    assert final_pair in valid_pairs, (
        f"final SourceParameters {final_pair} matches neither submitted config {valid_pairs} -- corrupted merge"
    )


def _create_queue(ctx, sqs, name, attributes=None):
    kwargs = {"QueueName": name, "tags": _RES_TAGS}
    if attributes:
        kwargs["Attributes"] = attributes
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_pipes_role(ctx, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipes-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "pipes.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAGS
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-pipes-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _wait_for_pipe_state(pipes, name, target_states, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    desc = None
    while time.monotonic() < deadline:
        desc = pipes.describe_pipe(Name=name)
        last = desc["CurrentState"]
        if last in target_states:
            return desc
        if last.endswith("_FAILED"):
            raise AssertionError(f"pipe {name} entered failure state {last}: {desc.get('StateReason')}")
        time.sleep(interval_s)
    raise AssertionError(f"pipe {name} did not reach {target_states} within {timeout_s}s (last={last})")


def _wait_for_pipe_deletion(pipes, name, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            pipes.describe_pipe(Name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(3)
    raise AssertionError(f"pipe {name} was not deleted within {timeout_s}s")


def _create_pipe_with_retry(pipes, timeout_s=90.0, interval_s=5.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            pipes.create_pipe(**kwargs)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ValidationException", "AccessDeniedException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_pipe_resilient(ctx, pipes, timeout_s=180.0, **kwargs):
    """CreatePipe, tolerating IAM role-trust propagation lag: newly created IAM
    roles/policies are not always immediately visible to other services
    (https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html).
    Retries the whole create-and-wait cycle within an overall deadline rather than
    once, since propagation lag is not bounded to a single retry."""
    name = kwargs["Name"]
    deadline = time.monotonic() + timeout_s
    _create_pipe_with_retry(pipes, timeout_s=max(5.0, deadline - time.monotonic()), **kwargs)
    desc = _wait_for_pipe_state(
        pipes, name, {"RUNNING", "STOPPED", "CREATE_FAILED"}, timeout_s=max(5.0, deadline - time.monotonic())
    )
    while desc["CurrentState"] == "CREATE_FAILED" and time.monotonic() < deadline:
        pipes.delete_pipe(Name=name)
        _wait_for_pipe_deletion(pipes, name, timeout_s=max(5.0, deadline - time.monotonic()))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(15.0, remaining))
        _create_pipe_with_retry(pipes, timeout_s=max(5.0, deadline - time.monotonic()), **kwargs)
        desc = _wait_for_pipe_state(
            pipes, name, {"RUNNING", "STOPPED", "CREATE_FAILED"}, timeout_s=max(5.0, deadline - time.monotonic())
        )
    if desc["CurrentState"] == "CREATE_FAILED":
        raise AssertionError(f"pipe {name} still CREATE_FAILED after retries within {timeout_s}s: {desc.get('StateReason')}")
    return desc


_SETTLED_PIPE_STATES = frozenset(
    {"STOPPED", "RUNNING", "CREATE_FAILED", "UPDATE_FAILED", "START_FAILED", "STOP_FAILED"}
)


def _stop_and_delete_pipe(pipes, name, timeout_s=180.0, interval_s=5.0):
    """Teardown: wait out any in-flight transition (DeletePipe refuses a pipe mid-transition),
    delete the pipe -- DeletePipe accepts a RUNNING or failed pipe, so no stop is needed -- and
    wait until it is gone. A refusal other than not-found is raised, so a leak is never silent."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            state = pipes.describe_pipe(Name=name)["CurrentState"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if state in _SETTLED_PIPE_STATES or time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    try:
        pipes.delete_pipe(Name=name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return
        raise
    _wait_for_pipe_deletion(pipes, name, timeout_s=timeout_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
