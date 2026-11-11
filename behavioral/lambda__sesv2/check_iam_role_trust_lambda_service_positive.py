"""iam-role-trust-lambda-service-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-role-trust-lambda-service-positive"
GROUP = "iam-trust"
SERVICES = ["lambda", "sesv2"]

_HANDLER_SRC = '''
import boto3

def handler(event, context):
    sts = boto3.client("sts")
    identity = sts.get_caller_identity()
    ses = boto3.client("sesv2")
    account = ses.get_account()
    return {
        "assumed_role_arn": identity["Arn"],
        "max_24_hour_send": account["SendQuota"]["Max24HourSend"],
    }
'''


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role whose AssumeRolePolicyDocument trusts lambda.amazonaws.com lets the Lambda
    service assume it -- the function actually runs with that role's temporary credentials
    (verified via sts.get_caller_identity from inside the handler) and can call sesv2."""
    role_name, role_arn = _create_role(
        ctx, "lambda.amazonaws.com", [{"Effect": "Allow", "Action": "ses:GetAccount", "Resource": "*"}]
    )
    fn = _create_function(ctx, role_arn, _HANDLER_SRC)
    result = _invoke(ctx, fn, {})

    arn = result["assumed_role_arn"]
    assert arn.startswith("arn:aws:sts::") and ":assumed-role/" in arn, arn
    assert role_name in arn, f"expected role {role_name!r} in assumed-role ARN {arn!r}"

    direct_quota = ctx.client("sesv2").get_account()["SendQuota"]["Max24HourSend"]
    assert isinstance(result["max_24_hour_send"], (int, float)), result
    assert result["max_24_hour_send"] == direct_quota, (result["max_24_hour_send"], direct_quota)


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


def _invoke(ctx, function_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=function_name, Payload=json.dumps(payload).encode("utf-8"))
    raw = resp["Payload"].read()
    body = json.loads(raw) if raw else {}
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation raised {resp['FunctionError']}: {body}")
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
