"""concurrent-start-pipe-single-winner."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-start-pipe-single-winner"
GROUP = "concurrency"
SERVICES = ["pipes"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two back-to-back StartPipe calls on the same STOPPED pipe: the first wins, the
    second (sent while the pipe is still starting) is rejected with ConflictException, and
    the pipe still lands cleanly in RUNNING (never a corrupted double transition)."""
    pipes = ctx.client("pipes")
    sqs = ctx.client("sqs")

    src_url, src_arn = _create_queue(ctx, sqs, ctx.unique_name("sim2real-pipes-src-"))
    tgt_url, tgt_arn = _create_queue(ctx, sqs, ctx.unique_name("sim2real-pipes-tgt-"))

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

    name = ctx.unique_name("sim2real-pipes-concstart-")
    _create_pipe_resilient(
        ctx,
        pipes,
        Name=name,
        Source=src_arn,
        Target=tgt_arn,
        RoleArn=role_arn,
        DesiredState="STOPPED",
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        Tags={"env": "sim2real"},
    )
    ctx.on_cleanup(lambda: _stop_and_delete_pipe(pipes, name))

    _wait_for_pipe_state(pipes, name, {"STOPPED"}, timeout_s=180)

    def _call():
        try:
            pipes.start_pipe(Name=name)
            return ("ok", None, None)
        except ClientError as e:
            return ("err", e.response["Error"]["Code"], e.response["Error"].get("Message"))

    # Sequential, so the second call deterministically meets the in-flight transition (a true
    # race has no documented outcome).
    results = [_call() for _ in range(2)]

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "err"]

    # exactly one racer must win the state transition
    assert len(successes) == 1, f"expected exactly one StartPipe success, got {results}"
    assert len(failures) == 1, f"expected exactly one StartPipe rejection, got {results}"
    assert failures[0][1] == "ConflictException", (
        f"expected the losing racer's error code to be ConflictException, got {failures[0][1]!r}"
    )
    expected_msg = f"Pipe {name} is updating concurrently."
    assert failures[0][2] == expected_msg, (
        f"expected the losing racer's message {expected_msg!r}, got {failures[0][2]!r}"
    )

    # and the pipe must still converge to a single coherent state, not a corrupted one
    desc = _wait_for_pipe_state(pipes, name, {"RUNNING"}, timeout_s=180)
    assert desc["CurrentState"] == "RUNNING", f"expected CurrentState=RUNNING, got {desc['CurrentState']!r}"
    assert desc["DesiredState"] == "RUNNING", f"expected DesiredState=RUNNING, got {desc['DesiredState']!r}"


def _create_queue(ctx, sqs, name, attributes=None):
    kwargs = {"QueueName": name, "tags": {"env": "sim2real"}}
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "env", "Value": "sim2real"}],
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
            # ValidationException/AccessDeniedException: IAM role-trust propagation lag.
            # ConflictException: the prior CreatePipe's delete (see _create_pipe_resilient)
            # has not yet fully propagated, so the name still reads as in-flight.
            if (
                code in ("ValidationException", "AccessDeniedException", "ConflictException")
                and time.monotonic() < deadline
            ):
                time.sleep(interval_s)
                continue
            raise


def _create_pipe_resilient(ctx, pipes, timeout_s=180.0, **kwargs):
    """CreatePipe, tolerating IAM role-trust propagation lag: newly created IAM
    roles/policies are not always immediately visible to other services
    (https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html)."""
    name = kwargs["Name"]
    _create_pipe_with_retry(pipes, **kwargs)
    desc = _wait_for_pipe_state(pipes, name, {"RUNNING", "STOPPED", "CREATE_FAILED"}, timeout_s=timeout_s)
    if desc["CurrentState"] == "CREATE_FAILED":
        pipes.delete_pipe(Name=name)
        _wait_for_pipe_deletion(pipes, name)
        # Bounded retry (deadline above), not a fixed sleep: recreate immediately and let
        # _create_pipe_with_retry absorb any ConflictException from delete propagation lag.
        _create_pipe_with_retry(pipes, **kwargs)
        desc = _wait_for_pipe_state(pipes, name, {"RUNNING", "STOPPED"}, timeout_s=timeout_s)
    return desc


def _stop_and_delete_pipe(pipes, name):
    try:
        desc = pipes.describe_pipe(Name=name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return
        raise
    if desc["CurrentState"] not in ("STOPPED", "CREATE_FAILED", "STOP_FAILED", "START_FAILED"):
        if desc["CurrentState"] != "STOPPING":
            pipes.stop_pipe(Name=name)
        _wait_for_pipe_state(pipes, name, {"STOPPED", "STOP_FAILED"}, timeout_s=180)
    pipes.delete_pipe(Name=name)
    _wait_for_pipe_deletion(pipes, name, timeout_s=180)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
