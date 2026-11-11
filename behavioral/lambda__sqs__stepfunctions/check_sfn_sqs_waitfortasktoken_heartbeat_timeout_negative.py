"""sfn-sqs-waitfortasktoken-heartbeat-timeout-negative."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-sqs-waitfortasktoken-heartbeat-timeout-negative"
GROUP = "task-token-lifecycle"
SERVICES = ["lambda", "stepfunctions", "sqs"]


# timing:real-time — workflow: 5 s https://docs.aws.amazon.com/step-functions/latest/dg/state-task.html
@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An SQS-fed callback task that is never heartbeated times out, and a subsequent
    SendTaskSuccess against that expired token is rejected — while a sibling execution
    that IS heartbeated in time still completes normally (in-file positive control)."""
    sfn_role_arn = _create_role(
        ctx,
        "states.amazonaws.com",
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}],
    )

    queue_ok = _create_queue(ctx)
    queue_timeout = _create_queue(ctx)

    definition = {
        "StartAt": "SendToQueue",
        "States": {
            "SendToQueue": {
                "Type": "Task",
                "Resource": "arn:aws:states:::sqs:sendMessage.waitForTaskToken",
                "Parameters": {
                    "QueueUrl.$": "$.queueUrl",
                    "MessageBody": {"token.$": "$$.Task.Token"},
                },
                "HeartbeatSeconds": 5,
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, definition, sfn_role_arn)
    sfn = ctx.client("stepfunctions")

    # --- positive control: heartbeat sent in time, execution succeeds ---
    # The sfn_role_arn's sqs:SendMessage grant can still be lagging IAM propagation
    # immediately after role creation even though CreateStateMachine itself succeeded;
    # retry with a fresh execution until one actually delivers its task token, rather
    # than guessing a fixed delay before the first one.
    exec_ok, token_ok = _start_execution_until_delivered(ctx, sm_arn, queue_ok["url"])
    sfn.send_task_heartbeat(taskToken=token_ok)
    sfn.send_task_success(taskToken=token_ok, output=json.dumps({"ok": True}))
    desc_ok = _wait_execution_terminal(ctx, exec_ok, timeout_s=60)
    assert desc_ok["status"] == "SUCCEEDED", desc_ok

    # --- negative: no heartbeat is ever sent, execution must time out ---
    exec_bad, token_bad = _start_execution_until_delivered(ctx, sm_arn, queue_timeout["url"])
    desc_bad = _wait_execution_terminal(ctx, exec_bad, timeout_s=90)
    assert desc_bad["status"] == "FAILED", f"expected FAILED, got {desc_bad['status']}"
    assert desc_bad.get("error") == "States.Timeout", desc_bad.get("error")
    # a heartbeat timeout carries no cause on DescribeExecution
    assert "cause" not in desc_bad, repr(desc_bad.get("cause"))

    # effect absent: a SendTaskSuccess against the now-expired token must be rejected
    code, message = _error_code(lambda: sfn.send_task_success(taskToken=token_bad, output="{}"))
    assert code == "TaskTimedOut", f"expected TaskTimedOut, got {code!r}"
    assert message == "Task Timed Out: 'Provided task does not exist anymore'", (
        f"unexpected TaskTimedOut message: {message!r}"
    )

    # and the execution outcome must remain unchanged by that rejected call
    desc_after = sfn.describe_execution(executionArn=exec_bad)
    assert desc_after["status"] == "FAILED", desc_after


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection but call succeeded: {result!r}")


def _create_role(ctx, principal, extra_statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": extra_statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-q-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"url": url}


def _receive_token(ctx, queue_url, timeout_s=30):
    """The task token from the next message on queue_url, or None if none arrives in time."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if msgs:
            body = json.loads(msgs[0]["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            return body["token"]
    return None


def _create_state_machine(ctx, definition, role_arn, timeout_s=60.0):
    """IAM role/policy grants can take a few seconds to propagate; retry the transient
    AccessDenied instead of guessing a fixed sleep."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sm-")
    deadline = time.monotonic() + timeout_s
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )
            break
        except ClientError as exc:
            last_err = exc
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"CreateStateMachine never succeeded within {timeout_s}s: {last_err}")
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn, input_dict):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-exec-")
    resp = sfn.start_execution(stateMachineArn=sm_arn, name=name, input=json.dumps(input_dict))
    return resp["executionArn"]


def _start_execution_until_delivered(ctx, sm_arn, queue_url, overall_timeout_s=90.0, attempt_timeout_s=20.0):
    """A fresh execution can fail its SendMessage before the executor role's grant has
    propagated; retry with a new execution (the failed one is inert and vanishes with the
    state machine at cleanup) until one delivers a task token."""
    deadline = time.monotonic() + overall_timeout_s
    while time.monotonic() < deadline:
        exec_arn = _start_execution(ctx, sm_arn, {"queueUrl": queue_url})
        token = _receive_token(ctx, queue_url, timeout_s=attempt_timeout_s)
        if token is not None:
            return exec_arn, token
    raise AssertionError(f"no execution delivered a task token on {queue_url} within {overall_timeout_s}s")


def _wait_execution_terminal(ctx, exec_arn, timeout_s=90, poll_s=3):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    desc = sfn.describe_execution(executionArn=exec_arn)
    while desc["status"] == "RUNNING" and time.monotonic() < deadline:
        time.sleep(poll_s)
        desc = sfn.describe_execution(executionArn=exec_arn)
    if desc["status"] == "RUNNING":
        raise AssertionError(f"execution still RUNNING after {timeout_s}s")
    return desc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
