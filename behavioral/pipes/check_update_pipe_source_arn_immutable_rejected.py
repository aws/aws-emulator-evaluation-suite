"""update-pipe-source-arn-immutable-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-pipe-source-arn-immutable-rejected"
GROUP = "overly-permissive"
SERVICES = ["pipes"]

_RES_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_IAM_TAGS = [{"Key": k, "Value": v} for k, v in _RES_TAGS.items()]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePipe with SourceParameters for a different source type than the pipe's SQS source is
    rejected with ValidationException (Source is immutable), leaving Source/SourceParameters
    unchanged; a same-type SourceParameters update still succeeds."""
    pipe = _create_test_pipe(ctx)
    pipes = ctx.client("pipes")

    before = pipes.describe_pipe(Name=pipe["name"])
    assert before["Source"] == pipe["source_arn"], f"expected Source={pipe['source_arn']}, got {before['Source']}"
    assert before["SourceParameters"]["SqsQueueParameters"]["BatchSize"] == 1, (
        f"expected initial BatchSize=1, got {before['SourceParameters']['SqsQueueParameters']}"
    )

    # SQS-sourced pipe given DynamoDB-stream parameters: the type mismatch must be rejected.
    # StartingPosition is omitted because UpdatePipeSourceDynamoDBStreamParameters lacks it.
    code, message, status = _error(
        lambda: pipes.update_pipe(
            Name=pipe["name"],
            RoleArn=pipe["role_arn"],
            SourceParameters={"DynamoDBStreamParameters": {"BatchSize": 5}},
        )
    )
    assert code == "ValidationException", f"expected a rejection, got {code}"
    assert status == 400, f"expected HTTP 400 for the rejection, got {status!r}"
    expected_message = '{"ValidationErrorFields":[{"Name":"DynamoDBStreamParameters","Message":"Invalid source parameter provided for source sqs."}]}'
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    after_reject = pipes.describe_pipe(Name=pipe["name"])
    assert after_reject["Source"] == pipe["source_arn"], "Source ARN must remain unchanged after a rejected update"
    assert "SqsQueueParameters" in after_reject["SourceParameters"], (
        f"expected SqsQueueParameters to survive the rejected update, got {after_reject['SourceParameters']}"
    )
    assert "DynamoDBStreamParameters" not in after_reject["SourceParameters"], (
        f"rejected DynamoDBStreamParameters must not have been applied, got {after_reject['SourceParameters']}"
    )
    assert after_reject["SourceParameters"]["SqsQueueParameters"]["BatchSize"] == 1, (
        f"expected BatchSize to remain 1 after the rejected update, got {after_reject['SourceParameters']}"
    )

    # Positive control: a same-type SourceParameters change on the same pipe succeeds,
    # proving the earlier rejection wasn't a blanket denial of UpdatePipe.
    pipes.update_pipe(
        Name=pipe["name"],
        RoleArn=pipe["role_arn"],
        SourceParameters={"SqsQueueParameters": {"BatchSize": 5}},
    )
    updated = _wait_for_pipe_state(ctx, pipe["name"])
    assert updated["CurrentState"] != "UPDATE_FAILED", f"legitimate update failed: {updated.get('StateReason')}"
    assert updated["Source"] == pipe["source_arn"], "Source ARN must remain unchanged even for a valid update"
    assert updated["SourceParameters"]["SqsQueueParameters"]["BatchSize"] == 5, (
        f"expected the legitimate same-type update to apply BatchSize=5, got {updated['SourceParameters']}"
    )


def _error(fn):
    """Return the (code, message, HTTP status) of the ClientError fn() raises; success raises."""
    try:
        result = fn()
    except ClientError as e:
        return (e.response["Error"]["Code"], e.response["Error"].get("Message"),
                e.response.get("ResponseMetadata", {}).get("HTTPStatusCode"))
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
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_pipes_trust_policy(), Tags=_IAM_TAGS)
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
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-pipes-q-"), tags=_RES_TAGS)["QueueUrl"]
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


def _create_test_pipe(ctx, desired_state: str = "STOPPED") -> dict:
    pipes = ctx.client("pipes")
    source_arn = _create_sqs_queue(ctx)
    target_arn = _create_sqs_queue(ctx)
    role_arn = _create_pipe_role(ctx, source_arn, target_arn)
    name = ctx.unique_name("sim2real-pipe-")
    deadline = time.monotonic() + 60.0
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
                Tags=_RES_TAGS,
            )
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
