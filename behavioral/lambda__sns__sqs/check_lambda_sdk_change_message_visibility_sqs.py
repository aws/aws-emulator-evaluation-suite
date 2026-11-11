"""lambda-sdk-change-message-visibility-sqs."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "lambda-sdk-change-message-visibility-sqs"
GROUP = "sdk-call"
SERVICES = ["lambda", "sns", "sqs"]

_CODE_CHANGE_VIS = """
import boto3

def handler(event, context):
    sqs = boto3.client("sqs")
    try:
        sqs.change_message_visibility(
            QueueUrl=event["queue_url"],
            ReceiptHandle=event["receipt_handle"],
            VisibilityTimeout=event["visibility_timeout"],
        )
        return {"ok": True}
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)
        return {"ok": False, "error_code": code}
"""


# timing:real-time — visibility: 25 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A message whose visibility a Lambda extends with ChangeMessageVisibility stays hidden past
    its original short timeout and is redelivered after the extension ends."""
    # Short original visibility window (documented SQS default-attribute behavior:
    # https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html)
    queue = _create_queue(ctx, attrs={"VisibilityTimeout": "5"})
    sqs = ctx.client("sqs")
    marker = ctx.unique_name("payload-")
    sqs.send_message(QueueUrl=queue["url"], MessageBody=marker)

    # set up the role/function BEFORE grabbing the message so the receive->extend gap is small
    role_arn = _create_role(
        ctx,
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "sqs:ChangeMessageVisibility", "Resource": queue["arn"]}
            ],
        },
    )
    fn = _create_function(ctx, role_arn, _CODE_CHANGE_VIS)

    receipt_handle = None
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and receipt_handle is None:
        resp = sqs.receive_message(QueueUrl=queue["url"], MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            if m["Body"] == marker:
                receipt_handle = m["ReceiptHandle"]
        if receipt_handle is None:
            time.sleep(1)
    assert receipt_handle is not None, "never received the seeded message"
    t_receive = time.monotonic()

    result = _invoke(
        ctx,
        fn,
        {"queue_url": queue["url"], "receipt_handle": receipt_handle, "visibility_timeout": 25},
    )
    assert result["ok"] is True, result

    # Poll a window that starts AFTER the original 5s timeout would have expired and stays
    # well inside the new 25s extension. If the extension had no effect, the message would
    # already be receivable again during this window.
    reappeared = False
    while time.monotonic() - t_receive < 15:
        if time.monotonic() - t_receive < 6:
            time.sleep(0.5)
            continue
        resp = sqs.receive_message(QueueUrl=queue["url"], MaxNumberOfMessages=10, WaitTimeSeconds=1)
        if any(m["Body"] == marker for m in resp.get("Messages", [])):
            reappeared = True
            break
    assert not reappeared, "message became visible again despite the extended visibility timeout"

    # The absence above is only meaningful if the extension is genuinely time-bound rather
    # than having swallowed the message outright. Confirm redelivery once the extended 25s
    # window (from receipt) elapses, on the same independent side channel.
    redelivered = False
    while time.monotonic() - t_receive < 45:
        if time.monotonic() - t_receive < 26:
            time.sleep(0.5)
            continue
        resp = sqs.receive_message(QueueUrl=queue["url"], MaxNumberOfMessages=10, WaitTimeSeconds=2)
        if any(m["Body"] == marker for m in resp.get("Messages", [])):
            redelivered = True
            break
    assert redelivered, "message never reappeared after the extended visibility timeout elapsed"


_PREFIX = "sim2real-snssqslambda-"


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _lambda_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_role(ctx: Any, inline_policy: dict | None) -> str:
    iam = ctx.client("iam")
    role_name = _xname(ctx, "role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if inline_policy is not None:
        iam.put_role_policy(RoleName=role_name, PolicyName="perm", PolicyDocument=json.dumps(inline_policy))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="perm"))
    return role_arn


def _wait_active(ctx: Any, name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {name} never became Active")


def _create_function(ctx: Any, role_arn: str, code: str, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    name = _xname(ctx, "fn")
    zip_bytes = _lambda_zip(code)
    deadline = time.monotonic() + 90.0
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Publish=True,
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    else:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_active(ctx, name)
    return name


def _invoke(ctx: Any, name: str, payload: dict) -> dict:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=name,
        Payload=json.dumps(payload).encode("utf-8"),
        InvocationType="RequestResponse",
    )
    body = json.loads(resp["Payload"].read())
    assert "FunctionError" not in resp, f"unexpected FunctionError: {resp.get('FunctionError')}, body={body}"
    return body


def _create_queue(ctx: Any, attrs: dict | None = None) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=_xname(ctx, "q"), Attributes=attrs or {}, tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
