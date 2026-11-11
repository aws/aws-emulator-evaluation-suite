"""start-pipe-without-execution-role-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-pipe-without-execution-role-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["pipes"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A pipe whose role lacks source/target permissions settles in CREATE_FAILED with a StateReason
    and a later StartPipe must not reach RUNNING; a permissioned sibling reaches RUNNING."""
    source = _create_sqs_queue(ctx, "src")
    target = _create_sqs_queue(ctx, "dst")

    # pipe #1: role with trust policy only, NO sqs permissions; Pipes validates them during
    # CreatePipe even with DesiredState=STOPPED.
    bare_role_arn = _create_pipes_role(ctx, with_permissions=False)
    bad_name = ctx.unique_name("sim2real-behav-pipe-bad-")
    _create_pipe(ctx, bad_name, source["arn"], target["arn"], bare_role_arn, desired_state="STOPPED")
    bad_result = _wait_for_pipe_state(ctx, bad_name, {"STOPPED", "CREATE_FAILED"})
    assert bad_result["CurrentState"] == "CREATE_FAILED", str(bad_result["CurrentState"])
    expected_reason = (
        "Input parameter is invalid from the request due to : The provided customer role does not "
        "have permissions to call ReceiveMessage on SQS"
    )
    assert bad_result.get("StateReason") == expected_reason, (
        f"expected StateReason {expected_reason!r}, got {bad_result.get('StateReason')!r}"
    )

    pipes = ctx.client("pipes")
    # StartPipe on a CREATE_FAILED pipe is accepted (it retries provisioning) but must not reach
    # RUNNING while the role still lacks permissions; a refusal raises ClientError.
    pipes.start_pipe(Name=bad_name)
    still_failed = _wait_for_pipe_state(ctx, bad_name, {"RUNNING", "START_FAILED", "CREATE_FAILED"})
    assert still_failed["CurrentState"] != "RUNNING", "pipe reached RUNNING despite role lacking permissions"

    # positive control: an identical pipe with a properly-permissioned role does start
    good_role_arn = _create_pipes_role(ctx, with_permissions=True)
    good_name = ctx.unique_name("sim2real-behav-pipe-good-")
    _create_pipe(ctx, good_name, source["arn"], target["arn"], good_role_arn, desired_state="STOPPED")
    good_stopped = _wait_for_pipe_state(ctx, good_name, {"STOPPED", "CREATE_FAILED"})
    assert good_stopped["CurrentState"] == "STOPPED", (
        f"positive control: expected STOPPED, got {good_stopped['CurrentState']!r} "
        f"reason={good_stopped.get('StateReason')!r}"
    )
    pipes.start_pipe(Name=good_name)
    good_running = _wait_for_pipe_state(ctx, good_name, {"RUNNING", "START_FAILED"})
    assert good_running["CurrentState"] == "RUNNING", (
        f"positive control: expected RUNNING, got {good_running['CurrentState']!r}"
    )


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


def _create_pipe(ctx, name, source_arn, target_arn, role_arn, desired_state="STOPPED"):
    pipes = ctx.client("pipes")
    _create_pipe_with_retry(
        pipes,
        Name=name,
        Source=source_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        Target=target_arn,
        RoleArn=role_arn,
        DesiredState=desired_state,
    )
    ctx.on_cleanup(lambda: _safe_delete_pipe(ctx, name))
    return name


def _create_pipe_with_retry(pipes, timeout_s=60.0, **kwargs):
    # IAM eventual consistency: Pipes may not yet see a role/policy that IAM just created,
    # surfacing as ValidationException/NotFoundException until its cache catches up.
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return pipes.create_pipe(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ValidationException", "NotFoundException"):
                last_err = err
                time.sleep(4)
                continue
            raise
    raise last_err


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
