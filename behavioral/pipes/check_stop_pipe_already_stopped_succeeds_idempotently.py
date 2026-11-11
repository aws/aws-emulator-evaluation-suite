"""stop-pipe-already-stopped-succeeds-idempotently."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-pipe-already-stopped-succeeds-idempotently"
GROUP = "state-machine"
SERVICES = ["pipes"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopPipe on an already-STOPPED pipe succeeds as a no-op rather than raising
    ConflictException, the pipe stays STOPPED, and a later StartPipe still works."""
    name = _build_pipe(ctx, desired_state="STOPPED", with_permissions=True)
    stopped = _wait_for_pipe_state(ctx, name, {"STOPPED", "CREATE_FAILED"})
    assert stopped["CurrentState"] == "STOPPED", f"pipe never reached STOPPED: {stopped}"

    pipes = ctx.client("pipes")
    # a refusal (e.g. ConflictException) raises ClientError and fails the check
    pipes.stop_pipe(Name=name)

    # effect: pipe is still STOPPED, not corrupted into some other state (poll, since a
    # same-state StopPipe may still churn through a brief transitional state before
    # settling back to STOPPED)
    still = _wait_for_pipe_state(ctx, name, {"STOPPED", "STOP_FAILED"})
    assert still["CurrentState"] == "STOPPED", f"expected CurrentState STOPPED, got {still['CurrentState']!r}"
    assert still["DesiredState"] == "STOPPED", f"expected DesiredState STOPPED, got {still['DesiredState']!r}"

    # positive control: the pipe is not stuck; a legitimate StartPipe still works
    pipes.start_pipe(Name=name)
    running = _wait_for_pipe_state(ctx, name, {"RUNNING", "START_FAILED"})
    assert running["CurrentState"] == "RUNNING", f"expected CurrentState RUNNING, got {running['CurrentState']!r}"


def _create_sqs_queue(ctx, tag):
    sqs = ctx.client("sqs")
    name = ctx.unique_name(f"sim2real-behav-{tag}-")
    url = sqs.create_queue(QueueName=name)["QueueUrl"]
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
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
    # IAM role trust/permissions are eventually consistent: CreatePipe can reject a role that
    # was just created with a transient ValidationException before it is visible to Pipes.
    # Retry the create itself, bounded, rather than guessing a fixed warm-up sleep.
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            pipes.create_pipe(
                Name=name,
                Source=source_arn,
                SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
                Target=target_arn,
                RoleArn=role_arn,
                DesiredState=desired_state,
            )
            ctx.on_cleanup(lambda: _safe_delete_pipe(ctx, name))
            return name
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ValidationException":
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"create_pipe never succeeded (role propagation?): {last_err}")


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
