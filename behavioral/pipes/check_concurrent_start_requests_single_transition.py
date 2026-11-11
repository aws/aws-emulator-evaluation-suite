"""concurrent-start-requests-single-transition."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-start-requests-single-transition"
GROUP = "concurrency"
SERVICES = ["pipes"]

_RES_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_RES_TAGS_KV = [{"Key": k, "Value": v} for k, v in _RES_TAGS.items()]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two StartPipe calls on the same STOPPED pipe, the second sent while the first is still
    STARTING, yield exactly one success and exactly one ConflictException; the pipe still ends
    up cleanly RUNNING, never in a corrupted intermediate state."""
    name = _build_pipe(ctx, desired_state="STOPPED", with_permissions=True)
    stopped = _wait_for_pipe_state(ctx, name, {"STOPPED", "CREATE_FAILED"})
    assert stopped["CurrentState"] == "STOPPED", f"pipe never reached STOPPED: {stopped}"

    pipes = ctx.client("pipes")

    def _attempt():
        try:
            pipes.start_pipe(Name=name)
            return "ok"
        except ClientError as err:
            return err.response["Error"]["Code"]

    # Back-to-back on one thread, so the second request lands inside the first one's STARTING
    # window whatever the host's thread scheduling.
    results = [_attempt(), _attempt()]

    successes = [r for r in results if r == "ok"]
    conflicts = [r for r in results if r == "ConflictException"]
    assert len(successes) == 1, f"expected exactly one winner, got {results}"
    assert len(conflicts) == 1, f"expected exactly one ConflictException loser, got {results}"

    running = _wait_for_pipe_state(ctx, name, {"RUNNING", "START_FAILED"})
    assert running["CurrentState"] == "RUNNING", f"pipe never settled cleanly: {running}"


def _create_sqs_queue(ctx, tag):
    sqs = ctx.client("sqs")
    name = ctx.unique_name(f"sim2real-behav-{tag}-")
    url = sqs.create_queue(QueueName=name, tags=_RES_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_pipes_role(ctx, with_permissions=True):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-pipes-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "pipes.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_RES_TAGS_KV
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if with_permissions:
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes", "sqs:SendMessage"],
                "Resource": "*",
            }],
        }
        policy_name = ctx.unique_name("sim2real-behav-pipes-policy-")
        iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _safe_delete_pipe(ctx, name):
    pipes = ctx.client("pipes")
    try:
        pipes.delete_pipe(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _create_pipe(ctx, name, source_arn, target_arn, role_arn, desired_state="STOPPED", timeout_s=90.0, interval_s=2.0):
    """CreatePipe, tolerating IAM role-trust propagation lag: a newly created role/policy is not
    always immediately visible to Pipes, which reports that as ValidationException or
    AccessDeniedException on the role rather than any state on the pipe itself."""
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while True:
        try:
            pipes.create_pipe(
                Name=name,
                Source=source_arn,
                SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
                Target=target_arn,
                RoleArn=role_arn,
                DesiredState=desired_state,
                Tags=_RES_TAGS,
            )
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ValidationException", "AccessDeniedException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            if code in ("ValidationException", "AccessDeniedException") and _budget_spent(ctx):
                raise TimeoutError(f"CreatePipe {name} role propagation: the run budget ended first; not graded") from err
            raise
    ctx.on_cleanup(lambda: _safe_delete_pipe(ctx, name))
    return name


def _wait_for_pipe_state(ctx, name, target_states, timeout_s=240.0, interval_s=1.0):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    desc = None
    while time.monotonic() < deadline:
        desc = pipes.describe_pipe(Name=name)
        last = desc["CurrentState"]
        if last in target_states:
            return desc
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"pipe {name} {target_states}: the run budget ended first; not graded")
    raise AssertionError(f"pipe {name} never reached {target_states}, last state was {last}")


def _build_pipe(ctx, desired_state="STOPPED", with_permissions=True):
    source = _create_sqs_queue(ctx, "src")
    target = _create_sqs_queue(ctx, "dst")
    role_arn = _create_pipes_role(ctx, with_permissions=with_permissions)
    name = ctx.unique_name("sim2real-behav-pipe-")
    _create_pipe(ctx, name, source["arn"], target["arn"], role_arn, desired_state=desired_state)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
