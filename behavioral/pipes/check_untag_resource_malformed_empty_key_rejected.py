"""untag-resource-malformed-empty-key-rejected."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-malformed-empty-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["pipes"]


def _raw_pipes_client(ctx):
    """A pipes client with client-side parameter validation off, so the empty key reaches the
    service and its rejection is observed rather than a local ParamValidationError."""
    return ctx.client("pipes", config=Config(parameter_validation=False))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource with an empty-string tag key is rejected server-side (keys need length >= 1)
    with ValidationException, leaving existing tags intact; untagging the real key still
    succeeds."""
    pipe = _create_test_pipe(ctx, tags={"keep": "value"})
    pipes = ctx.client("pipes")
    raw_pipes = _raw_pipes_client(ctx)

    code, message = _error(lambda: raw_pipes.untag_resource(resourceArn=pipe["arn"], tagKeys=[""]))
    assert code == "ValidationException", (
        f"an empty-string tag key must be rejected server-side, got {code}"
    )
    assert message == "[tagKeys]", f"unexpected UntagResource message {message!r}"

    tags_after_reject = pipes.list_tags_for_resource(resourceArn=pipe["arn"])["tags"]
    assert tags_after_reject == {"keep": "value"}, "a rejected UntagResource call must not remove tags"

    # Positive control: untagging the real key on the same pipe succeeds.
    pipes.untag_resource(resourceArn=pipe["arn"], tagKeys=["keep"])
    tags_after_valid = pipes.list_tags_for_resource(resourceArn=pipe["arn"])["tags"]
    assert tags_after_valid == {}


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
