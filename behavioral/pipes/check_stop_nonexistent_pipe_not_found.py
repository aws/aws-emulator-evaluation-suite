"""stop-nonexistent-pipe-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-nonexistent-pipe-not-found"
GROUP = "error-semantics"
SERVICES = ["pipes"]

_RES_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-pipe"}
_TAGS_KV = [{"Key": k, "Value": v} for k, v in _RES_TAGS.items()]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopPipe against a pipe Name that was created then fully deleted returns
    NotFoundException, and a real pipe (positive control) still stops normally."""
    pipes = ctx.client("pipes")
    src_arn, dst_arn = _create_queue_pair(ctx)
    role_arn = _create_pipe_role(ctx, src_arn, dst_arn)

    deleted_name = ctx.unique_name("sim2real-pipe-deleted-")
    _create_pipe_with_retry(
        ctx,
        pipes,
        Name=deleted_name,
        Source=src_arn,
        Target=dst_arn,
        RoleArn=role_arn,
        DesiredState="STOPPED",
        Tags=_RES_TAGS,
    )
    _wait_for_pipe_state(pipes, deleted_name, {"STOPPED"}, {"CREATE_FAILED"})
    pipes.delete_pipe(Name=deleted_name)
    _wait_for_pipe_deleted(pipes, deleted_name)

    code, message = _client_error(lambda: pipes.stop_pipe(Name=deleted_name))
    assert code == "NotFoundException", (
        f"expected NotFoundException stopping a deleted pipe, got {code!r}"
    )
    expected_message = f"Pipe {deleted_name} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # positive control: StopPipe on a real, existing (RUNNING) pipe works
    live_name = ctx.unique_name("sim2real-pipe-")
    _create_pipe_with_retry(
        ctx,
        pipes,
        Name=live_name,
        Source=src_arn,
        Target=dst_arn,
        RoleArn=role_arn,
        DesiredState="RUNNING",
        Tags=_RES_TAGS,
    )
    ctx.on_cleanup(lambda: _cleanup_delete_pipe(pipes, live_name))
    _wait_for_pipe_state(pipes, live_name, {"RUNNING"}, {"CREATE_FAILED"})

    pipes.stop_pipe(Name=live_name)
    stopped = _wait_for_pipe_state(pipes, live_name, {"STOPPED"}, {"STOP_FAILED"})
    assert stopped["CurrentState"] == "STOPPED", (
        f"expected StopPipe on a live, existing pipe to reach STOPPED, got {stopped['CurrentState']!r}"
    )


def _client_error(fn):
    """Run a call that must be refused and return its (code, message). An accepted call
    raises: an emulator accepting what real AWS refuses must fail loudly, not read as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_queue_pair(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    src_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-pipes-src-"), tags=_RES_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))
    dst_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-pipes-dst-"), tags=_RES_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dst_url))
    src_arn = sqs.get_queue_attributes(QueueUrl=src_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    dst_arn = sqs.get_queue_attributes(QueueUrl=dst_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return src_arn, dst_arn


def _create_pipe_role(ctx, source_arn: str, target_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipes-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "pipes.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAGS_KV
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sim2real-pipes-inline-policy"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes", "sqs:ChangeMessageVisibility"],
                "Resource": source_arn,
            },
            {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arn},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_pipe_with_retry(ctx, pipes_client, timeout_s: float = 90.0, interval_s: float = 5.0, **kwargs):
    # IAM role trust/permissions are eventually consistent (IAM docs: changes can take
    # seconds to propagate); poll CreatePipe itself rather than asserting immediately.
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return pipes_client.create_pipe(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ValidationException":
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"create_pipe never succeeded (role propagation?): {last_err}")


def _wait_for_pipe_state(pipes_client, name, success_states, failure_states=frozenset(), timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = pipes_client.describe_pipe(Name=name)
        last = resp["CurrentState"]
        if last in success_states:
            return resp
        if last in failure_states:
            raise AssertionError(f"pipe {name} entered failure state {last}: {resp.get('StateReason')}")
        time.sleep(interval_s)
    raise AssertionError(f"pipe {name} never reached {success_states}, last state={last}")


def _wait_for_pipe_deleted(pipes_client, name, timeout_s=180.0, interval_s=5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            pipes_client.describe_pipe(Name=name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"pipe {name} was not deleted within {timeout_s}s")


def _cleanup_delete_pipe(pipes_client, name, timeout_s=120.0, interval_s=5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            pipes_client.delete_pipe(Name=name)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code == "ConflictException":
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"failed to delete pipe {name} within cleanup window")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
