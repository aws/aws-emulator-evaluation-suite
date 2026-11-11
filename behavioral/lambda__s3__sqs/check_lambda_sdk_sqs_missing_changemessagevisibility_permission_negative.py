"""lambda-sdk-sqs-missing-changemessagevisibility-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sdk-sqs-missing-changemessagevisibility-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "s3", "sqs"]

_HANDLER_CODE = """
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    sqs = boto3.client("sqs")
    resp = sqs.receive_message(QueueUrl=event["queue_url"], MaxNumberOfMessages=1, WaitTimeSeconds=10)
    msgs = resp.get("Messages", [])
    if not msgs:
        return {"status": "empty"}
    try:
        sqs.change_message_visibility(
            QueueUrl=event["queue_url"],
            ReceiptHandle=msgs[0]["ReceiptHandle"],
            VisibilityTimeout=60,
        )
        return {"status": "ok"}
    except ClientError as err:
        return {"status": "error", "code": err.response["Error"]["Code"], "message": err.response["Error"]["Message"]}
"""

_VISIBILITY_TIMEOUT_S = 7
_MANAGED_TAGS = {"sim2real:managed": "true"}


# timing:real-time — visibility: 7 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:rejection", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A role lacking sqs:ChangeMessageVisibility fails to extend visibility, so the message
    becomes redeliverable on the original schedule; a role WITH the permission (positive
    control, same file, separate queue) successfully extends it and blocks redelivery."""
    sqs = ctx.client("sqs")

    denied_queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-visdenied-"),
        Attributes={"VisibilityTimeout": str(_VISIBILITY_TIMEOUT_S)},
        tags=_MANAGED_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=denied_queue_url))
    denied_queue_arn = sqs.get_queue_attributes(QueueUrl=denied_queue_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    sqs.send_message(QueueUrl=denied_queue_url, MessageBody="vis-denied-fixture")

    denied_role_arn = _create_lambda_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:GetQueueAttributes"],
                "Resource": denied_queue_arn,
            }
        ],
    )
    denied_fn = _create_lambda_function(ctx, denied_role_arn, _HANDLER_CODE)
    denied_result = _invoke_lambda(ctx, denied_fn, {"queue_url": denied_queue_url})
    assert denied_result["status"] == "error", f"expected error status, got {denied_result!r}"
    assert denied_result["code"] == "AccessDenied", f"expected AccessDenied, got {denied_result['code']!r}"
    account = denied_role_arn.split(":")[4]
    denied_role_name = denied_role_arn.rsplit("/", 1)[1]
    expected_message = (
        f"User: arn:aws:sts::{account}:assumed-role/{denied_role_name}/{denied_fn} is not authorized to perform: "
        f"sqs:changemessagevisibility on resource: {denied_queue_arn} "
        "because no identity-based policy allows the sqs:changemessagevisibility action"
    )
    assert denied_result["message"] == expected_message, (
        f"unexpected AccessDenied message: {denied_result['message']!r}"
    )

    # Effect must be absent: the extension never took hold, so the message reappears once the
    # ORIGINAL visibility timeout elapses (well before a would-be 60s extension).
    deadline = time.monotonic() + (_VISIBILITY_TIMEOUT_S + 15)
    redelivered = False
    while time.monotonic() < deadline and not redelivered:
        resp = sqs.receive_message(QueueUrl=denied_queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=3)
        if resp.get("Messages"):
            redelivered = True
    assert redelivered, "message was never redelivered even though the visibility extension was denied"

    # Positive control: a role WITH sqs:ChangeMessageVisibility, on a separate queue, actually
    # extends visibility and the message stays hidden past the original timeout.
    allowed_queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-visallowed-"),
        Attributes={"VisibilityTimeout": str(_VISIBILITY_TIMEOUT_S)},
        tags=_MANAGED_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=allowed_queue_url))
    allowed_queue_arn = sqs.get_queue_attributes(QueueUrl=allowed_queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    sqs.send_message(QueueUrl=allowed_queue_url, MessageBody="vis-allowed-fixture")

    allowed_role_arn = _create_lambda_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes"],
                "Resource": allowed_queue_arn,
            }
        ],
    )
    allowed_fn = _create_lambda_function(ctx, allowed_role_arn, _HANDLER_CODE)
    allowed_result = _invoke_lambda(ctx, allowed_fn, {"queue_url": allowed_queue_url})
    assert allowed_result["status"] == "ok", f"positive control failed: {allowed_result}"

    stay_hidden_deadline = time.monotonic() + (_VISIBILITY_TIMEOUT_S + 8)
    while time.monotonic() < stay_hidden_deadline:
        resp = sqs.receive_message(QueueUrl=allowed_queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        if resp.get("Messages"):
            raise AssertionError("positive control: message was redelivered despite the extended visibility timeout")


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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY,
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )
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
        Tags=dict(_MANAGED_TAGS),
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
