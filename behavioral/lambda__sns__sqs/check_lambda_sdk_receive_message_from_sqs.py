"""lambda-sdk-receive-message-from-sqs."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "lambda-sdk-receive-message-from-sqs"
GROUP = "sdk-call"
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


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda function whose role grants sqs:ReceiveMessage pulls the seeded message via boto3."""
    queue = _create_queue(ctx)
    sqs = ctx.client("sqs")
    marker = ctx.unique_name("payload-")
    sqs.send_message(QueueUrl=queue["url"], MessageBody=marker)

    role_arn = _create_role(
        ctx,
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "sqs:ReceiveMessage", "Resource": queue["arn"]}
            ],
        },
    )
    fn = _create_function(ctx, role_arn, _CODE_RECEIVE)
    result = _invoke(ctx, fn, {"queue_url": queue["url"]})

    assert result["ok"] is True, result
    assert marker in result["bodies"], result

    # independent read at the destination: the message the Lambda claims to have
    # received must actually be gone from view on the real queue (hidden by the
    # visibility timeout the in-lambda receive_message call set), not merely echoed
    # back in the invoke response.
    followup = sqs.receive_message(QueueUrl=queue["url"], MaxNumberOfMessages=10, WaitTimeSeconds=0)
    still_visible = [m["Body"] for m in followup.get("Messages", [])]
    assert marker not in still_visible, ("message still visible after the in-lambda receive", still_visible)


_PREFIX = "sim2real-snssqslambda-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


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
        Tags=_xsvc_tags_kv(),
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
                Tags=_xsvc_resource_tags(),
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    else:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    # The function auto-creates /aws/lambda/<name> on first invoke; that log group survives
    # function deletion, so delete it
    # too.
    ctx.on_cleanup(
        lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    )
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
        QueueName=_xname(ctx, "q"), Attributes=attrs or {}, tags=_xsvc_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
