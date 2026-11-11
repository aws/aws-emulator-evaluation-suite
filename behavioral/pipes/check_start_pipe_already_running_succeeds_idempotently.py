"""start-pipe-already-running-succeeds-idempotently."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-pipe-already-running-succeeds-idempotently"
GROUP = "state-machine"
SERVICES = ["pipes"]

_RES_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_KV_TAGS = [{"Key": k, "Value": v} for k, v in _RES_TAGS.items()]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartPipe on an already-RUNNING pipe succeeds as a no-op rather than raising
    ConflictException, the pipe stays RUNNING, and a later StopPipe still works."""
    name = _build_pipe(ctx, desired_state="RUNNING", with_permissions=True)
    running = _wait_for_pipe_state(ctx, name, {"RUNNING", "CREATE_FAILED"})
    assert running["CurrentState"] == "RUNNING", f"pipe never reached RUNNING: {running}"

    pipes = ctx.client("pipes")
    # ConflictException is reserved for concurrent transitions; a refusal here fails the check.
    pipes.start_pipe(Name=name)

    # effect: pipe is still RUNNING, not corrupted into some other state (poll, since a
    # same-state StartPipe may still churn through a brief transitional state before
    # settling back to RUNNING)
    still = _wait_for_pipe_state(ctx, name, {"RUNNING", "START_FAILED"})
    assert still["CurrentState"] == "RUNNING", f"expected CurrentState=RUNNING after redundant StartPipe, got {still['CurrentState']!r}"
    assert still["DesiredState"] == "RUNNING", f"expected DesiredState=RUNNING after redundant StartPipe, got {still['DesiredState']!r}"

    # positive control: the pipe is not stuck; a legitimate StopPipe still works
    pipes.stop_pipe(Name=name)
    stopped = _wait_for_pipe_state(ctx, name, {"STOPPED", "STOP_FAILED"})
    assert stopped["CurrentState"] == "STOPPED", f"expected CurrentState=STOPPED after positive-control StopPipe, got {stopped['CurrentState']!r}"


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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_KV_TAGS
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


def _create_pipe(ctx, name, source_arn, target_arn, role_arn, desired_state="STOPPED", timeout_s=90.0, interval_s=5.0):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
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
            # bounded retry for IAM role-trust propagation lag, not an unconditional wait
            if code in ("ValidationException", "AccessDeniedException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise
    ctx.on_cleanup(lambda: _safe_delete_pipe(ctx, name))
    return name


def _wait_for_pipe_state(ctx, name, target_states, timeout_s=240.0, interval_s=5.0):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    last = None
    desc = None
    while time.monotonic() < deadline:
        desc = pipes.describe_pipe(Name=name)
        last = desc["CurrentState"]
        if last in target_states:
            return desc
        time.sleep(interval_s)
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
