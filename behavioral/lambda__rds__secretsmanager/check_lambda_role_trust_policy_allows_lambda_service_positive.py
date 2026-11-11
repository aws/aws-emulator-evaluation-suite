"""lambda-role-trust-policy-allows-lambda-service-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-role-trust-policy-allows-lambda-service-positive"
GROUP = "iam-trust"
SERVICES = ["lambda", "rds", "secretsmanager"]

_HANDLER_CODE = """
def handler(event, context):
    return {"result": "ok", "echo": event}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role whose AssumeRolePolicyDocument trusts lambda.amazonaws.com can be attached
    to a function at creation time and is actually assumed by the Lambda service at
    invoke time (the function executes and returns its payload)."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-lambda-trust-ok-")
    trust_policy = {
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    )

    function_name = ctx.unique_name("sim2real-lambda-trust-ok-fn-")
    zip_bytes = _make_lambda_zip(_HANDLER_CODE)

    create_resp = _create_function_with_retry(
        ctx,
        lam,
        FunctionName=function_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": zip_bytes},
        Timeout=15,
        MemorySize=128,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    assert create_resp["Role"] == role_arn, (
        f"expected CreateFunction to echo back Role={role_arn!r}, got {create_resp['Role']!r}"
    )

    _wait_function_active(ctx, lam, function_name)

    invoke_resp = lam.invoke(
        FunctionName=function_name,
        Payload=json.dumps({"ping": "pong"}).encode("utf-8"),
    )
    assert invoke_resp["StatusCode"] == 200, (
        f"expected Invoke StatusCode=200, got {invoke_resp['StatusCode']}"
    )
    assert "FunctionError" not in invoke_resp, (
        f"expected no FunctionError, got {invoke_resp.get('FunctionError')!r}"
    )
    payload = json.loads(invoke_resp["Payload"].read())
    expected_payload = {"result": "ok", "echo": {"ping": "pong"}}
    assert payload == expected_payload, (
        f"expected invoke payload {expected_payload!r}, got {payload!r}"
    )


def _make_lambda_zip(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _error_code(fn) -> str | None:
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


def _create_function_with_retry(ctx, lam, timeout_s: float = 60.0, **kwargs: Any):
    """IAM role trust-policy changes can lag briefly before Lambda can assume the
    role; retry CreateFunction on the transient 'cannot be assumed' error rather
    than sleeping a fixed duration."""
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "cannot be assumed" in msg:
                last_err = e
                time.sleep(3)
                continue
            raise
    assert last_err is not None, "retry loop exited without ever calling CreateFunction"
    raise last_err


def _wait_function_active(ctx, lam, function_name: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=function_name)
        if cfg["State"] == "Active":
            return
        if cfg["State"] == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg}")
        time.sleep(2)
    raise AssertionError(f"function {function_name} never became Active within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
