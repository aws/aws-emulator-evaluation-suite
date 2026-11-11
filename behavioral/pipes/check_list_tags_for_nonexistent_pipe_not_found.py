"""list-tags-for-nonexistent-pipe-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-nonexistent-pipe-not-found"
GROUP = "error-semantics"
SERVICES = ["pipes"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on a pipe ARN that has since been deleted returns
    NotFoundException, not an empty tag set."""
    pipe = _create_test_pipe(ctx, tags={"keep": "value"})
    pipes = ctx.client("pipes")

    # sanity: tags are visible while the pipe still exists.
    live_tags = pipes.list_tags_for_resource(resourceArn=pipe["arn"])["tags"]
    assert live_tags == {"keep": "value"}, f"positive control: expected {{'keep': 'value'}}, got {live_tags}"

    _delete_pipe(ctx, pipe["name"])
    _wait_pipe_gone(ctx, pipe["name"])

    code, message = _client_error(lambda: pipes.list_tags_for_resource(resourceArn=pipe["arn"]))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    expected_message = "Resource was not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Run a call that must be refused and return its (code, message). An accepted call
    raises: an emulator accepting what real AWS refuses must fail loudly, not read as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _pipes_trust_policy() -> str:
    return json.dumps(
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


def _create_pipe_role(ctx, source_arn: str, target_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipes-role-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_pipes_trust_policy())
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
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
    policy_name = ctx.unique_name("sim2real-pipes-policy-")
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_doc)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_sqs_queue(ctx) -> str:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-pipes-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]


def _wait_for_pipe_state(ctx, name: str, timeout_s: float = 120.0, interval_s: float = 3.0):
    pipes = ctx.client("pipes")
    terminal = {"RUNNING", "STOPPED", "CREATE_FAILED", "UPDATE_FAILED"}
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = pipes.describe_pipe(Name=name)
        if last["CurrentState"] in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"pipe {name} never reached a terminal state, last={last}")


def _wait_pipe_gone(ctx, name: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> None:
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            pipes.describe_pipe(Name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NotFoundException":
                raise
            return
        time.sleep(interval_s)
    raise AssertionError(f"pipe {name} was never fully removed within {timeout_s}s")


def _delete_pipe(ctx, name: str) -> None:
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        try:
            pipes.delete_pipe(Name=name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code == "ConflictException":
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"could not delete pipe {name}")


def _create_test_pipe(ctx, desired_state: str = "STOPPED", tags: dict | None = None) -> dict:
    pipes = ctx.client("pipes")
    source_arn = _create_sqs_queue(ctx)
    target_arn = _create_sqs_queue(ctx)
    role_arn = _create_pipe_role(ctx, source_arn, target_arn)
    name = ctx.unique_name("sim2real-pipe-")
    kwargs = dict(
        Name=name,
        Source=source_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        Target=target_arn,
        RoleArn=role_arn,
        DesiredState=desired_state,
    )
    if tags:
        kwargs["Tags"] = tags
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            pipes.create_pipe(**kwargs)
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                last_err = e
                time.sleep(3)
                continue
            raise
    else:
        raise AssertionError(f"CreatePipe never succeeded after role propagation wait: {last_err}")
    ctx.on_cleanup(lambda: _delete_pipe(ctx, name))
    desc = _wait_for_pipe_state(ctx, name)
    if desc["CurrentState"] == "CREATE_FAILED":
        raise AssertionError(f"pipe creation failed: {desc.get('StateReason')}")
    return {
        "name": name,
        "arn": desc["Arn"],
        "source_arn": source_arn,
        "target_arn": target_arn,
        "role_arn": role_arn,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
