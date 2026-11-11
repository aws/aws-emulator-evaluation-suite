"""lambda-sdk-sqs-change-message-visibility-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sdk-sqs-change-message-visibility-positive"
GROUP = "sdk-call"
SERVICES = ["lambda", "s3", "sqs"]

_HANDLER_CODE = """
import boto3

def handler(event, context):
    sqs = boto3.client("sqs")
    resp = sqs.receive_message(QueueUrl=event["queue_url"], MaxNumberOfMessages=1, WaitTimeSeconds=10)
    msgs = resp.get("Messages", [])
    if not msgs:
        return {"status": "empty"}
    sqs.change_message_visibility(
        QueueUrl=event["queue_url"],
        ReceiptHandle=msgs[0]["ReceiptHandle"],
        VisibilityTimeout=60,
    )
    return {"status": "ok"}
"""


# timing:real-time — visibility: 6 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A message whose visibility a Lambda extends with ChangeMessageVisibility is not redelivered,
    while a control message received at the same time on a twin queue without the extension is
    redelivered."""
    sqs = ctx.client("sqs")
    # Short default visibility timeout so a failed extension would show up as a fast redelivery.
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-vistimeout-"),
        Attributes={"VisibilityTimeout": "6"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    sqs.send_message(QueueUrl=queue_url, MessageBody="visibility-extend-fixture")

    control_queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-vistimeout-ctrl-"),
        Attributes={"VisibilityTimeout": "6"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=control_queue_url))
    sqs.send_message(QueueUrl=control_queue_url, MessageBody="visibility-control-fixture")

    role_arn = _create_lambda_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes"],
                "Resource": queue_arn,
            }
        ],
    )
    fn_name = _create_lambda_function(ctx, role_arn, _HANDLER_CODE)

    result = _invoke_lambda(ctx, fn_name, {"queue_url": queue_url})
    assert result["status"] == "ok", f"lambda handler did not report ok: {result!r}"

    # Receive the control message directly (no ChangeMessageVisibility) at roughly the same
    # instant, so its 6s hidden window runs alongside the primary's extended one.
    control_resp = sqs.receive_message(QueueUrl=control_queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
    control_msgs = control_resp.get("Messages", [])
    if not control_msgs:
        raise AssertionError("control message was not receivable — cannot establish the redelivery baseline")

    # The queue's default visibility timeout is 6s; the function extended the primary message
    # to 60s. Poll well past 6s: the primary must stay invisible (extension held) while the
    # control — received but never extended — must reappear (the mechanism is live).
    deadline = time.monotonic() + 14
    control_redelivered = False
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        if resp.get("Messages"):
            raise AssertionError("message was redelivered despite the extended visibility timeout")
        if not control_redelivered:
            ctrl_resp = sqs.receive_message(QueueUrl=control_queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=0)
            if ctrl_resp.get("Messages"):
                control_redelivered = True

    if not control_redelivered:
        raise AssertionError(
            "control message (visibility never extended) was never redelivered — this queue "
            "wiring cannot distinguish an honored extension from a target that never redelivers "
            "at all"
        )


_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


def _zip_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx, statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY)
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))

    policy_name = ctx.unique_name("sim2real-behav-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_lambda_function(ctx, role_arn: str, code: str, env: dict[str, str] | None = None, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-behav-fn-")
    kwargs: dict[str, Any] = dict(
        FunctionName=fn_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _zip_code(code)},
        Timeout=timeout,
        Publish=True,
    )
    if env:
        kwargs["Environment"] = {"Variables": env}

    last_err: Exception | None = None
    for _ in range(12):
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as err:
            last_err = err
            time.sleep(5)
    else:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return fn_name


def _invoke_lambda(ctx, fn_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=fn_name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode("utf-8"),
    )
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation errored: {body}")
    return body


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
