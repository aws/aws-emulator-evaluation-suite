"""sqs-send-message-task-without-permission-is-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-send-message-task-without-permission-is-denied"
GROUP = "task_integrations"
SERVICES = ["stepfunctions", "sqs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A sqs:sendMessage task whose execution role lacks sqs:SendMessage is caught as
    SQS.AmazonSQSException and delivers nothing, while a sibling role that holds the
    permission succeeds and does deliver.
    """
    sqs = ctx.client("sqs")

    queue = _create_queue(ctx)
    denied_role_name, denied_role = _create_sfn_role(ctx, statements=[])
    _, allowed_role = _create_sfn_role(ctx, statements=[
        {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue["arn"]},
    ])
    denied_sm = _create_state_machine(ctx, queue["url"], denied_role)
    allowed_sm = _create_state_machine(ctx, queue["url"], allowed_role)

    _, desc = _run_to_terminal(ctx, denied_sm, expect_denied=True)
    assert desc["status"] == "FAILED", (
        f"execution ended {desc['status']!r}, expected FAILED: {desc.get('cause')!r}"
    )
    assert desc["error"] == "SQS.AmazonSQSException", f"the task's error was {desc['error']!r}"
    masked = _mask_request_id(desc["cause"], denied_role_name)
    assert masked == (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{denied_role_name}/<session>"
        f" is not authorized to perform: sqs:sendmessage on resource: {queue['arn']}"
        " because no identity-based policy allows the sqs:sendmessage action "
        "(Service: AmazonSQS; Status Code: 403; Error Code: AccessDenied; "
        "Request ID: <id>; Proxy: null)"
    ), f"the task's cause was {desc['cause']!r}"

    # The denied send delivered nothing.
    assert _receive_all(ctx, queue["url"]) == [], "a denied sqs:sendMessage must deliver nothing"

    # Positive control: the identical task, same queue, with the permission granted, succeeds
    # and the message actually lands in the queue.
    _, ok_desc = _run_to_terminal(ctx, allowed_sm, expect_denied=False)
    assert ok_desc["status"] == "SUCCEEDED", (
        f"the allowed sibling ended {ok_desc['status']!r}: "
        f"{ok_desc.get('error')!r} {ok_desc.get('cause')!r}"
    )
    delivered = _receive_all(ctx, queue["url"])
    assert len(delivered) == 1 and json.loads(delivered[0]["Body"]) == {"marker": "ok"}, (
        f"the allowed sibling must deliver its message, got {delivered!r}"
    )


# ===== helpers =====

def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_queue(ctx) -> dict:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-q-")
    url = sqs.create_queue(QueueName=name, tags={"sim2real": CHECK[:200]})["QueueUrl"]
    ctx.on_cleanup(_teardown(
        lambda: sqs.delete_queue(QueueUrl=url), "AWS.SimpleQueueService.NonExistentQueue"))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _receive_all(ctx, queue_url):
    sqs = ctx.client("sqs")
    out = []
    while True:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        msgs = resp.get("Messages", [])
        if not msgs:
            return out
        out.extend(msgs)


def _mask_request_id(cause, role_name):
    import re
    masked = re.sub(r"Request ID: [0-9a-zA-Z-]+;", "Request ID: <id>;", cause or "")
    return re.sub(rf"/{re.escape(role_name)}/[0-9a-zA-Z]+\b",
                  f"/{role_name}/<session>", masked)


def _create_role(ctx, trust_service, statements):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK[:200]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    if statements:
        iam.put_role_policy(
            RoleName=name, PolicyName="inline",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
        ctx.on_cleanup(_teardown(
            lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"), "NoSuchEntity"))
    return name, arn


def _create_sfn_role(ctx, statements):
    return _create_role(ctx, "states.amazonaws.com", statements)


def _create_state_machine(ctx, queue_url, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    definition = {
        "Comment": "sim2real: one sqs:sendMessage task",
        "StartAt": "Send",
        "States": {
            "Send": {
                "Type": "Task",
                "Resource": "arn:aws:states:::sqs:sendMessage",
                "Parameters": {"QueueUrl": queue_url, "MessageBody": json.dumps({"marker": "ok"})},
                "End": True,
            },
        },
    }
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn,
                type="STANDARD", tags=[{"key": "sim2real", "value": CHECK[:200]}],
            )["stateMachineArn"]
            ctx.on_cleanup(_teardown(
                lambda: sfn.delete_state_machine(stateMachineArn=arn), "StateMachineDoesNotExist"))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


_TRUST_PROPAGATION_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "UnrecognizedClientException",
    "InvalidClientTokenId",
    "security token included in the request is invalid",
)


def _start(ctx, sm_arn):
    sfn = ctx.client("stepfunctions")
    arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"), input="{}",
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, arn))
    return arn


def _best_effort_stop(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="sim2real-cleanup", cause="cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _wait_terminal(ctx, exec_arn, *, timeout_s=60.0, interval_s=1.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _run_to_terminal(ctx, sm_arn, *, expect_denied, propagation_s=90.0):
    """Retry on IAM trust-assumption propagation only; a real AccessDenied-from-missing-permission
    is never mistaken for that, since its cause never names role assumption."""
    retry_until = time.monotonic() + propagation_s
    while True:
        exec_arn = _start(ctx, sm_arn)
        desc = _wait_terminal(ctx, exec_arn)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _TRUST_PROPAGATION_MARKERS):
            return exec_arn, desc
        if time.monotonic() >= retry_until:
            return exec_arn, desc
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
