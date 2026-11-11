"""lambda-sdk-apigateway-get-rest-apis-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sdk-apigateway-get-rest-apis-positive"
GROUP = "sdk-call"
SERVICES = ["apigateway", "cloudformation", "lambda"]

_HANDLER_CODE = """
import boto3

def handler(event, context):
    apig = boto3.client("apigateway")
    target_name = event["api_name"]
    apis = []
    position = None
    while True:
        kwargs = {"limit": 500}
        if position:
            kwargs["position"] = position
        resp = apig.get_rest_apis(**kwargs)
        apis.extend(resp.get("items", []))
        position = resp.get("position")
        if not position:
            break
    match = next((a for a in apis if a["name"] == target_name), None)
    return {"api_id": match["id"] if match else None}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda function whose role allows apigateway:GET lists REST APIs with boto3 and finds the
    API the check created by name."""
    apig = ctx.client("apigateway")
    api_name = ctx.unique_name("sim2real-cfa-api-")
    api_id = apig.create_rest_api(name=api_name, tags={"sim2real:managed": "true"})["id"]
    ctx.on_cleanup(lambda: apig.delete_rest_api(restApiId=api_id))

    role_arn = _create_lambda_role(ctx, [{"Effect": "Allow", "Action": "apigateway:GET", "Resource": "*"}])
    fn_name = _create_function(ctx, role_arn, _HANDLER_CODE)

    result = _invoke(ctx, fn_name, {"api_name": api_name})
    assert result.get("api_id") == api_id, f"expected api_id {api_id}, got {result}"


def _zip_code(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx, statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cfa-role-")
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))

    if statements:
        policy_name = ctx.unique_name("sim2real-cfa-policy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_function(ctx, role_arn: str, handler_code: str) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-cfa-fn-")
    code = _zip_code(handler_code)
    deadline = time.monotonic() + 60
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code},
                Timeout=30,
                Tags={"sim2real:managed": "true"},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    else:
        raise AssertionError(f"role never became assumable by lambda: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return name


def _invoke(ctx, function_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=function_name, Payload=json.dumps(payload).encode("utf-8"))
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation failed: {body}")
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
