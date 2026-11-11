"""sfn-sqs-fifo-missing-messagegroupid-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sfn-sqs-fifo-missing-messagegroupid-negative"
GROUP = "sfn-sqs-messaging"
SERVICES = ["lambda", "stepfunctions", "sqs"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Omitting the required MessageGroupId on a FIFO-queue sqs:sendMessage task fails
    the execution and delivers nothing; a sibling state machine that does supply
    MessageGroupId (positive control) succeeds and delivers exactly one message."""
    queue = _create_fifo_queue(ctx)
    role_arn = _create_sfn_role(ctx, ["sqs:SendMessage"])

    missing_definition = {
        "StartAt": "SendMissingGroup",
        "States": {
            "SendMissingGroup": {
                "Type": "Task",
                "Resource": "arn:aws:states:::sqs:sendMessage",
                "Parameters": {
                    "QueueUrl.$": "$.queueUrl",
                    "MessageBody.$": "$.body",
                },
                "End": True,
            }
        },
    }
    control_definition = {
        "StartAt": "SendWithGroup",
        "States": {
            "SendWithGroup": {
                "Type": "Task",
                "Resource": "arn:aws:states:::sqs:sendMessage",
                "Parameters": {
                    "QueueUrl.$": "$.queueUrl",
                    "MessageBody.$": "$.body",
                    "MessageGroupId.$": "$.groupId",
                },
                "End": True,
            }
        },
    }
    sm_missing = _create_state_machine_with_retry(
        ctx, ctx.unique_name("sim2real-sm-missing-"), missing_definition, role_arn
    )
    sm_control = _create_state_machine_with_retry(
        ctx, ctx.unique_name("sim2real-sm-control-"), control_definition, role_arn
    )

    # Positive control first (also serves as an IAM-propagation warm-up for the role):
    # same queue, MessageGroupId supplied -> succeeds and delivers exactly one message.
    pos_execution = _start_and_wait_with_iam_retry(
        ctx, sm_control, {"queueUrl": queue["url"], "body": "control-group-body", "groupId": "group-1"}
    )
    assert pos_execution["status"] == "SUCCEEDED", pos_execution.get("cause", pos_execution)

    received = _poll_receive(ctx, queue["url"], min_count=1, timeout_s=30.0, attribute_names=["MessageGroupId"])
    assert len(received) == 1, received
    assert received[0]["Body"] == "control-group-body", received
    assert received[0]["Attributes"]["MessageGroupId"] == "group-1", received

    # Negative: FIFO queue requires MessageGroupId -> execution must fail, nothing delivered.
    # Permissions are already known-good (from the control above), so this failure is
    # attributable to the missing MessageGroupId, not to IAM propagation lag.
    neg_execution = _start_and_wait(
        ctx, sm_missing, {"queueUrl": queue["url"], "body": "missing-group-body"}
    )
    assert neg_execution["status"] == "FAILED", neg_execution
    assert neg_execution.get("error") == "SQS.AmazonSQSException", neg_execution
    cause = neg_execution.get("cause", "")
    assert "MissingParameter" in cause, cause
    assert "MessageGroupId" in cause, cause

    sqs = ctx.client("sqs")
    empty = sqs.receive_message(QueueUrl=queue["url"], MaxNumberOfMessages=10, WaitTimeSeconds=3)
    assert empty.get("Messages", []) == [], empty


def _create_fifo_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-sfnq-") + ".fifo"
    url = sqs.create_queue(
        QueueName=name, Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_sfn_role(ctx, sqs_actions: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": sqs_actions, "Resource": "*"}],
    }
    policy_name = ctx.unique_name("sim2real-sfn-policy-")
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_state_machine_with_retry(
    ctx, name: str, definition: dict[str, Any], role_arn: str, timeout_s: float = 45.0
) -> str:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD"
            )
            arn = resp["stateMachineArn"]
            ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
            return arn
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                last_err = e
                time.sleep(2)
                continue
            raise
    raise last_err


def _wait_execution(ctx, execution_arn: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> dict[str, Any]:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sfn.describe_execution(executionArn=execution_arn)
        if resp["status"] != "RUNNING":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"execution {execution_arn} did not reach a terminal state within {timeout_s}s")


def _start_and_wait(ctx, state_machine_arn: str, input_obj: dict[str, Any], timeout_s: float = 60.0) -> dict[str, Any]:
    sfn = ctx.client("stepfunctions")
    resp = sfn.start_execution(
        stateMachineArn=state_machine_arn,
        name=ctx.unique_name("exec-"),
        input=json.dumps(input_obj),
    )
    return _wait_execution(ctx, resp["executionArn"], timeout_s=timeout_s)


def _start_and_wait_with_iam_retry(
    ctx, state_machine_arn: str, input_obj: dict[str, Any], overall_timeout_s: float = 90.0, timeout_s: float = 60.0
) -> dict[str, Any]:
    """IAM role trust/permissions attached to the SFN role can take a few seconds to
    propagate after create_role/put_role_policy. A task execution that runs before that
    propagation completes fails with an AccessDenied-style cause even though the policy
    is (eventually) correct. Retry fresh executions until the failure is no longer an
    IAM-propagation artifact, or overall_timeout_s elapses."""
    deadline = time.monotonic() + overall_timeout_s
    execution = _start_and_wait(ctx, state_machine_arn, input_obj, timeout_s=timeout_s)
    while execution["status"] == "FAILED":
        cause = str(execution.get("cause", "")) + str(execution.get("error", ""))
        if not ("not authorized" in cause.lower() or "accessdenied" in cause.lower()):
            return execution
        if time.monotonic() >= deadline:
            return execution
        time.sleep(3)
        execution = _start_and_wait(ctx, state_machine_arn, input_obj, timeout_s=timeout_s)
    return execution


def _poll_receive(
    ctx, queue_url: str, min_count: int = 1, timeout_s: float = 30.0, attribute_names: list[str] | None = None
) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    collected: list[dict[str, Any]] = []
    kwargs: dict[str, Any] = {"QueueUrl": queue_url, "MaxNumberOfMessages": 10, "WaitTimeSeconds": 5}
    if attribute_names:
        kwargs["AttributeNames"] = attribute_names
    deadline = time.monotonic() + timeout_s
    while len(collected) < min_count and time.monotonic() < deadline:
        resp = sqs.receive_message(**kwargs)
        for m in resp.get("Messages", []):
            collected.append(m)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return collected


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
