"""desired-state-persists-through-list-pipes."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "desired-state-persists-through-list-pipes"
GROUP = "state-machine"
SERVICES = ["pipes"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After StartPipe/StopPipe, DesiredState and CurrentState reported by ListPipes match
    DescribePipe, both while RUNNING and after transitioning back to STOPPED."""
    pipes = ctx.client("pipes")
    res_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-pipe"}
    src_arn, dst_arn = _create_queue_pair(ctx, res_tags)
    role_arn = _create_pipe_role(ctx, src_arn, dst_arn, res_tags)
    name = ctx.unique_name("sim2real-pipe-")

    _create_pipe_with_retry(
        ctx,
        pipes,
        Name=name,
        Source=src_arn,
        Target=dst_arn,
        RoleArn=role_arn,
        DesiredState="STOPPED",
        Tags=res_tags,
    )
    ctx.on_cleanup(lambda: _cleanup_delete_pipe(pipes, name))
    _wait_for_pipe_state(pipes, name, {"STOPPED"}, {"CREATE_FAILED"})

    pipes.start_pipe(Name=name)
    _wait_for_pipe_state(pipes, name, {"RUNNING"}, {"START_FAILED"})

    describe_running = pipes.describe_pipe(Name=name)
    list_entry_running = _find_pipe_summary(pipes, name)
    assert describe_running["CurrentState"] == "RUNNING"
    assert describe_running["DesiredState"] == "RUNNING"
    assert list_entry_running["CurrentState"] == describe_running["CurrentState"]
    assert list_entry_running["DesiredState"] == describe_running["DesiredState"]

    pipes.stop_pipe(Name=name)
    _wait_for_pipe_state(pipes, name, {"STOPPED"}, {"STOP_FAILED"})

    describe_stopped = pipes.describe_pipe(Name=name)
    list_entry_stopped = _find_pipe_summary(pipes, name)
    assert describe_stopped["CurrentState"] == "STOPPED"
    assert describe_stopped["DesiredState"] == "STOPPED"
    assert list_entry_stopped["CurrentState"] == describe_stopped["CurrentState"]
    assert list_entry_stopped["DesiredState"] == describe_stopped["DesiredState"]


def _find_pipe_summary(pipes_client, name):
    resp = pipes_client.list_pipes(NamePrefix=name)
    matches = [p for p in resp["Pipes"] if p["Name"] == name]
    assert len(matches) == 1, f"expected exactly one ListPipes entry for {name}, got {len(matches)}"
    return matches[0]


def _create_queue_pair(ctx, res_tags: dict[str, str]) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    src_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-pipes-src-"), tags=res_tags)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))
    dst_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-pipes-dst-"), tags=res_tags)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dst_url))
    src_arn = sqs.get_queue_attributes(QueueUrl=src_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    dst_arn = sqs.get_queue_attributes(QueueUrl=dst_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return src_arn, dst_arn


def _create_pipe_role(ctx, source_arn: str, target_arn: str, res_tags: dict[str, str]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipes-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "pipes.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_tags = [{"Key": k, "Value": v} for k, v in res_tags.items()]
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=role_tags
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
