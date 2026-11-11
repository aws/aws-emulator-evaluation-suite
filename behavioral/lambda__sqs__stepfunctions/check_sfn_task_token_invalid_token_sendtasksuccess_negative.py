"""sfn-task-token-invalid-token-sendtasksuccess-negative."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-task-token-invalid-token-sendtasksuccess-negative"
GROUP = "task-token-lifecycle"
SERVICES = ["lambda", "stepfunctions", "sqs"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendTaskSuccess with a fabricated task token is rejected and resumes no execution,
    while a real token issued by a live waitForTaskToken execution still resolves it
    (in-file positive control)."""
    sfn_role_arn = _create_role(
        ctx,
        "states.amazonaws.com",
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}],
    )

    queue = _create_queue(ctx)
    definition = {
        "StartAt": "SendToQueue",
        "States": {
            "SendToQueue": {
                "Type": "Task",
                "Resource": "arn:aws:states:::sqs:sendMessage.waitForTaskToken",
                "Parameters": {
                    "QueueUrl": queue["url"],
                    "MessageBody": {"token.$": "$$.Task.Token"},
                },
                "HeartbeatSeconds": 60,
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, definition, sfn_role_arn)
    sfn = ctx.client("stepfunctions")

    # positive control: a real, live token successfully resumes its execution. The role's
    # policy may not be assumable by the state machine the instant after creation (IAM
    # eventual consistency), so retry with a fresh execution -- bounded, not a blind sleep --
    # until one actually reaches SendToQueue and delivers a token.
    exec_arn, real_token = _await_first_live_token(ctx, sm_arn, queue["url"], timeout_s=60)
    sfn.send_task_success(taskToken=real_token, output=json.dumps({"ok": True}))
    desc = _wait_execution_terminal(ctx, exec_arn, timeout_s=60)
    assert desc["status"] == "SUCCEEDED", desc

    # negative: a fabricated token is structurally invalid and rejected outright.
    fake_token = "not-a-real-task-token-" + ctx.unique_name("x")
    code, message = _error_code(lambda: sfn.send_task_success(taskToken=fake_token, output="{}"))
    assert code == "InvalidToken", f"expected InvalidToken, got {code!r}"
    assert message == "Invalid Token: 'Invalid token'", f"unexpected InvalidToken message: {message!r}"

    # effect absent: the real execution's outcome remains the only thing that happened.
    desc_after = sfn.describe_execution(executionArn=exec_arn)
    assert desc_after["status"] == "SUCCEEDED", desc_after
    assert json.loads(desc_after["output"]) == {"ok": True}, desc_after


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_role(ctx, principal, extra_statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-q-"))["QueueUrl"]
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


def _await_first_live_token(ctx, sm_arn, queue_url, timeout_s=60):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        exec_arn = _start_execution(ctx, sm_arn, {})
        token = _receive_token(ctx, queue_url, timeout_s=10)
        if token is not None:
            return exec_arn, token
        last_status = sfn.describe_execution(executionArn=exec_arn)["status"]
    raise AssertionError(
        f"SendToQueue never delivered a task token within {timeout_s}s "
        f"(IAM role/policy propagation); last execution status {last_status!r}"
    )


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sm-")
    resp = sfn.create_state_machine(
        name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD"
    )
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn, input_dict):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-exec-")
    resp = sfn.start_execution(stateMachineArn=sm_arn, name=name, input=json.dumps(input_dict))
    return resp["executionArn"]


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
