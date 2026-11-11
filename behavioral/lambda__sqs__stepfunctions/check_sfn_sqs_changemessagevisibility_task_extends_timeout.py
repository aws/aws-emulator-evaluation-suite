"""sfn-sqs-changemessagevisibility-task-extends-timeout."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-sqs-changemessagevisibility-task-extends-timeout"
GROUP = "sfn-sqs-messaging"
SERVICES = ["lambda", "stepfunctions", "sqs"]

# The original window must survive IAM role/state-machine propagation (both have
# their own tens-of-seconds retry loops below) plus dispatch latency before the
# Task ever calls ChangeMessageVisibility, so it cannot be a couple of seconds --
# see the ordering comment in run().
ORIGINAL_VISIBILITY_S = 15
EXTENDED_VISIBILITY_S = 45


# timing:real-time — visibility: 45 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An SFN aws-sdk:sqs:changeMessageVisibility task extends an in-flight message's visibility: it
    stays hidden past its original timeout and reappears after the extended window elapses."""
    queue = _create_queue(ctx)
    role_arn = _create_sfn_role(ctx, ["sqs:ChangeMessageVisibility"])
    sqs = ctx.client("sqs")

    definition = {
        "StartAt": "ExtendVisibility",
        "States": {
            "ExtendVisibility": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:sqs:changeMessageVisibility",
                "Parameters": {
                    "QueueUrl.$": "$.queueUrl",
                    "ReceiptHandle.$": "$.receiptHandle",
                    "VisibilityTimeout": EXTENDED_VISIBILITY_S,
                },
                "End": True,
            }
        },
    }
    # Create every prerequisite BEFORE the message is received. create_state_machine
    # and start_execution each retry on AccessDeniedException for up to 45s/90s to
    # absorb IAM role-trust propagation -- if the message were received first, that
    # same propagation delay would burn down its visibility window and the receipt
    # handle would go stale before the Task ever got to call
    # ChangeMessageVisibility, failing a correct target for a setup-latency reason
    # that has nothing to do with the property under test.
    sm_arn = _create_state_machine_with_retry(ctx, ctx.unique_name("sim2real-sm-"), definition, role_arn)

    sqs.send_message(QueueUrl=queue["url"], MessageBody="visibility-test")
    receipt_handle = None
    receive_time = None
    deadline = time.monotonic() + 20.0
    while receipt_handle is None and time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue["url"], MaxNumberOfMessages=1, VisibilityTimeout=ORIGINAL_VISIBILITY_S, WaitTimeSeconds=5
        )
        msgs = resp.get("Messages", [])
        if msgs:
            receipt_handle = msgs[0]["ReceiptHandle"]
            receive_time = time.monotonic()
    assert receipt_handle is not None, "never received the seeded message"

    execution = _start_and_wait_with_iam_retry(
        ctx, sm_arn, {"queueUrl": queue["url"], "receiptHandle": receipt_handle}
    )
    assert execution["status"] == "SUCCEEDED", execution.get("cause", execution)

    # Wait past the *original* visibility window (with margin) but well inside the
    # extended window, and assert the message is still NOT visible -- proving the
    # ChangeMessageVisibility task call actually took effect.
    early_wait_s = ORIGINAL_VISIBILITY_S + 5.0
    while time.monotonic() - receive_time < early_wait_s:
        time.sleep(0.5)
    early = sqs.receive_message(QueueUrl=queue["url"], MaxNumberOfMessages=1, WaitTimeSeconds=2)
    assert early.get("Messages", []) == [], f"message became visible before extended timeout: {early}"

    # After the extended window fully elapses the message should become visible again
    # (proving it was extended, not deleted or lost).
    reappeared = []
    deadline = receive_time + EXTENDED_VISIBILITY_S + 15.0
    while time.monotonic() < deadline and not reappeared:
        resp = sqs.receive_message(QueueUrl=queue["url"], MaxNumberOfMessages=1, WaitTimeSeconds=3)
        reappeared.extend(resp.get("Messages", []))
    assert len(reappeared) == 1 and reappeared[0]["Body"] == "visibility-test", reappeared


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sfnq-"))["QueueUrl"]
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
    """Start fresh executions until one fails for a reason other than IAM propagation, which
    can take seconds after create_role/put_role_policy and surfaces as an AccessDenied-style cause;
    gives up after overall_timeout_s."""
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
