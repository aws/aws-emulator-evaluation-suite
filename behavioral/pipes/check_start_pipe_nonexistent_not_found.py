"""start-pipe-nonexistent-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-pipe-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["pipes"]
_RES_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartPipe on an unknown pipe name returns NotFoundException, while StartPipe on a
    real pipe (positive control, in the same file) succeeds normally."""
    pipes = ctx.client("pipes")
    ghost_name = ctx.unique_name("sim2real-behav-ghost-")

    code, message = _client_error(lambda: pipes.start_pipe(Name=ghost_name))
    assert code == "NotFoundException", f"expected NotFoundException starting {ghost_name!r}, got {code}"
    expected_message = f"Pipe {ghost_name} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # positive control: a real pipe can be started
    name = _build_pipe(ctx, desired_state="STOPPED", with_permissions=True)
    stopped = _wait_for_pipe_state(ctx, name, {"STOPPED", "CREATE_FAILED"})
    assert stopped["CurrentState"] == "STOPPED", f"expected {name} STOPPED, got {stopped['CurrentState']}"
    pipes.start_pipe(Name=name)
    running = _wait_for_pipe_state(ctx, name, {"RUNNING", "START_FAILED"})
    assert running["CurrentState"] == "RUNNING", f"expected {name} RUNNING, got {running['CurrentState']}"


def _client_error(fn):
    """Run a call that must be refused and return its (code, message). An accepted call
    raises: an emulator accepting what real AWS refuses must fail loudly, not read as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _RES_TAGS.items()],
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


def _create_pipe(ctx, name, source_arn, target_arn, role_arn, desired_state="STOPPED", timeout_s=60.0, interval_s=5.0):
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
            # IAM role/policy propagation is eventually consistent; retry only that specific,
            # transient rejection, bounded by a deadline.
            if err.response["Error"]["Code"] != "ValidationException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
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
