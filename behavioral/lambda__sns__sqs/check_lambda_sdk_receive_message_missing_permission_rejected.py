"""lambda-sdk-receive-message-missing-permission-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "lambda-sdk-receive-message-missing-permission-rejected"
GROUP = "permission-boundary"
SERVICES = ["lambda", "sns", "sqs"]

_CODE_RECEIVE = """
import boto3

def handler(event, context):
    sqs = boto3.client("sqs")
    try:
        resp = sqs.receive_message(
            QueueUrl=event["queue_url"],
            MaxNumberOfMessages=10,
            WaitTimeSeconds=5,
        )
        messages = resp.get("Messages", [])
        return {"ok": True, "bodies": [m["Body"] for m in messages]}
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)
        return {"ok": False, "error_code": code}
"""


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role without sqs:ReceiveMessage gets AccessDenied and never consumes the message;
    a role with the permission (positive control) then succeeds on the same, still-present message."""
    queue = _create_queue(ctx)
    sqs = ctx.client("sqs")
    marker = ctx.unique_name("payload-")
    sqs.send_message(QueueUrl=queue["url"], MessageBody=marker)

    deny_role = _create_role(ctx, None)
    deny_fn = _create_function(ctx, deny_role, _CODE_RECEIVE)
    denied = _invoke(ctx, deny_fn, {"queue_url": queue["url"]})
    assert denied["ok"] is False, denied
    assert denied["error_code"] == "AccessDenied", denied

    # effect absent: the unauthorized call must not have consumed the message
    still_there = sqs.receive_message(
        QueueUrl=queue["url"], MaxNumberOfMessages=10, WaitTimeSeconds=2, VisibilityTimeout=0
    )
    bodies = [m["Body"] for m in still_there.get("Messages", [])]
    assert marker in bodies, "message should still be on the queue after the denied receive attempt"

    # positive control: same message, role WITH the permission succeeds
    allow_role = _create_role(
        ctx,
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "sqs:ReceiveMessage", "Resource": queue["arn"]}
            ],
        },
    )
    allow_fn = _create_function(ctx, allow_role, _CODE_RECEIVE)
    # bounded retry: the inline policy just attached to allow_role can lag IAM's real propagation
    # window, so a single invoke can observe a transient AccessDenied even though the grant is correct
    allowed = _invoke_until(ctx, allow_fn, {"queue_url": queue["url"]}, lambda r: r["ok"] is True)
    assert allowed["ok"] is True, allowed
    assert marker in allowed["bodies"], allowed


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


def _invoke_until(ctx: Any, name: str, payload: dict, predicate, timeout_s: float = 60.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last: dict | None = None
    while time.monotonic() < deadline:
        last = _invoke(ctx, name, payload)
        if predicate(last):
            return last
        time.sleep(3)
    raise AssertionError(f"invoke of {name} never satisfied predicate within {timeout_s}s: {last}")


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
