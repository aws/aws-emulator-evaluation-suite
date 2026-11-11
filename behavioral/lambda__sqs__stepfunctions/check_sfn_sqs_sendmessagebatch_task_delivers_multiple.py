"""sfn-sqs-sendmessagebatch-task-delivers-multiple."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-sqs-sendmessagebatch-task-delivers-multiple"
GROUP = "sfn-sqs-messaging"
SERVICES = ["lambda", "stepfunctions", "sqs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An SFN task using the aws-sdk:sqs:sendMessageBatch integration delivers every
    batch entry to the target queue, verified end-to-end via ReceiveMessage."""
    queue = _create_queue(ctx)
    role_arn = _create_sfn_role(ctx, ["sqs:SendMessage", "sqs:SendMessageBatch"])

    definition = {
        "StartAt": "SendBatch",
        "States": {
            "SendBatch": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:sqs:sendMessageBatch",
                "Parameters": {
                    "QueueUrl.$": "$.queueUrl",
                    "Entries": [
                        {"Id": "e1", "MessageBody": "batch-entry-0"},
                        {"Id": "e2", "MessageBody": "batch-entry-1"},
                        {"Id": "e3", "MessageBody": "batch-entry-2"},
                    ],
                },
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine_with_retry(
        ctx, ctx.unique_name("sim2real-sm-"), definition, role_arn
    )

    execution = _start_and_wait_with_iam_retry(ctx, sm_arn, {"queueUrl": queue["url"]})
    assert execution["status"] == "SUCCEEDED", execution.get("cause", execution)

    output = json.loads(execution["output"])
    assert len(output["Successful"]) == 3, output

    received = _poll_receive(ctx, queue["url"], min_count=3, timeout_s=30.0)
    bodies = {m["Body"] for m in received}
    assert bodies == {"batch-entry-0", "batch-entry-1", "batch-entry-2"}, bodies


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sfnq-"), tags={"sim2real": CHECK})["QueueUrl"]
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
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
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
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
    ctx,
    queue_url: str,
    min_count: int = 1,
    timeout_s: float = 30.0,
    message_attribute_names: list[str] | None = None,
    attribute_names: list[str] | None = None,
) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    collected: list[dict[str, Any]] = []
    kwargs: dict[str, Any] = {"QueueUrl": queue_url, "MaxNumberOfMessages": 10, "WaitTimeSeconds": 5}
    if message_attribute_names:
        kwargs["MessageAttributeNames"] = message_attribute_names
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
