"""lambda-execution-role-wrong-trust-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-execution-role-wrong-trust-negative"
GROUP = "iam-trust"
SERVICES = ["lambda", "sesv2"]

_HANDLER_SRC = '''
import boto3

def handler(event, context):
    client = boto3.client("sesv2")
    resp = client.get_account()
    return {"ok": True, "max_24_hour_send": resp["SendQuota"]["Max24HourSend"]}
'''


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateFunction refuses a role trusting ec2.amazonaws.com (InvalidParameterValueException,
    exact message) and no function exists, while a correctly trusted role's function reads a
    positive Max24HourSend from SES."""
    _, wrong_role_arn = _create_role(
        ctx, "ec2.amazonaws.com", [{"Effect": "Allow", "Action": "ses:GetAccount", "Resource": "*"}]
    )
    missing_fn_name, code, message = _attempt_create_function_expect_rejection(
        ctx, wrong_role_arn, _HANDLER_SRC
    )
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for a role trusting ec2.amazonaws.com "
        f"instead of lambda.amazonaws.com, got {code!r}"
    )
    expected_message = "The role defined for the function cannot be assumed by Lambda."
    assert message == expected_message, f"{message!r} != {expected_message!r}"
    lam = ctx.client("lambda")
    absent_code, absent_message = _error(lambda: lam.get_function(FunctionName=missing_fn_name))
    assert absent_code == "ResourceNotFoundException", (
        f"expected no function to exist after the rejected CreateFunction, "
        f"got GetFunction error {absent_code!r}"
    )
    expected_absent = (
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{missing_fn_name}"
    )
    assert absent_message == expected_absent, f"{absent_message!r} != {expected_absent!r}"

    _, good_role_arn = _create_role(
        ctx, "lambda.amazonaws.com", [{"Effect": "Allow", "Action": "ses:GetAccount", "Resource": "*"}]
    )
    good_fn = _create_function(ctx, good_role_arn, _HANDLER_SRC)
    result = _invoke(ctx, good_fn, {})
    assert result["ok"] is True, f"expected the sesv2 call through the correctly-trusted role to succeed, got {result!r}"
    assert result["max_24_hour_send"] > 0, (
        f"expected sesv2 GetAccount to report a positive Max24HourSend quota, got {result!r}"
    )


def _zip_lambda_code(handler_src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_src)
    return buf.getvalue()


def _create_role(ctx, principal_service: str, statements: list[dict[str, Any]]) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sesv2lam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": principal_service}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))
    if statements:
        policy_name = f"{role_name}-inline"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_name, role_arn


def _wait_active(ctx, function_name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=function_name)
        state = cfg.get("State")
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(f"function {function_name} failed to become active: {cfg}")
        time.sleep(2)
    raise AssertionError(f"function {function_name} never became Active within {timeout_s}s")


def _create_function(ctx, role_arn: str, handler_src: str, timeout_s: float = 90.0) -> str:
    lam = ctx.client("lambda")
    function_name = ctx.unique_name("sim2real-sesv2lam-fn-")
    zip_bytes = _zip_lambda_code(handler_src)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                MemorySize=128,
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidParameterValueException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    _wait_active(ctx, function_name)
    return function_name


def _attempt_create_function_expect_rejection(
    ctx, role_arn: str, handler_src: str
) -> tuple[str, str, str]:
    """Attempts CreateFunction with role_arn, which is expected to be rejected synchronously
    because the role's trust policy cannot be assumed by lambda.amazonaws.com. Returns
    (function_name, error_code, error_message). If CreateFunction ever unexpectedly succeeds, the created
    function is cleaned up and an AssertionError is raised."""
    lam = ctx.client("lambda")
    function_name = ctx.unique_name("sim2real-sesv2lam-fn-")
    zip_bytes = _zip_lambda_code(handler_src)
    try:
        ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
        lam.create_function(
            FunctionName=function_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": zip_bytes},
            Timeout=30,
            MemorySize=128,
            Tags={"sim2real": CHECK},
        )
        ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
        raise AssertionError(
            "create_function unexpectedly succeeded with a role whose trust policy does "
            "not include lambda.amazonaws.com"
        )
    except ClientError as e:
        error = e.response["Error"]
        return function_name, error["Code"], error.get("Message", "")


def _invoke(ctx, function_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=function_name, Payload=json.dumps(payload).encode("utf-8"))
    raw = resp["Payload"].read()
    body = json.loads(raw) if raw else {}
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation raised {resp['FunctionError']}: {body}")
    return body


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


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
