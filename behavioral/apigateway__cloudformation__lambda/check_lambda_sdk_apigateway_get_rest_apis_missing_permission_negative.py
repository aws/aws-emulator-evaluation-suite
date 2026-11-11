"""lambda-sdk-apigateway-get-rest-apis-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sdk-apigateway-get-rest-apis-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "cloudformation", "lambda"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-cfa"}
_TAGS_KV = [{"Key": k, "Value": v} for k, v in _TAGS.items()]

_HANDLER_CODE = """
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    apig = boto3.client("apigateway")
    try:
        resp = apig.get_rest_apis(limit=500)
    except ClientError as exc:
        return {"error": exc.response["Error"]["Code"]}
    return {"names": [a["name"] for a in resp.get("items", [])]}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role without apigateway:GET is refused GetRestApis with AccessDeniedException and returns no
    API data, while a sibling function whose role has it lists the target API."""
    apig = ctx.client("apigateway")
    api_name = ctx.unique_name("sim2real-cfa-api-")
    api_id = apig.create_rest_api(name=api_name, tags=_TAGS)["id"]
    ctx.on_cleanup(lambda: apig.delete_rest_api(restApiId=api_id))

    _role_with_name, role_with = _create_lambda_role(
        ctx, [{"Effect": "Allow", "Action": "apigateway:GET", "Resource": "*"}]
    )
    fn_with = _create_function(ctx, role_with, _HANDLER_CODE)

    role_without_name, role_without = _create_lambda_role(ctx, [])
    fn_without = _create_function(ctx, role_without, _HANDLER_CODE)

    control = _invoke(ctx, fn_with, {})
    assert "error" not in control, f"positive control unexpectedly failed: {control}"
    assert api_name in control["names"], f"expected {api_name!r} in {control['names']}"

    denied = _invoke(ctx, fn_without, {})
    assert denied.get("error") == "AccessDeniedException", f"unexpected result: {denied}"
    assert "names" not in denied, f"denied call still returned API list: {denied}"

    # Restore: grant the identical permission to the SAME role that was just denied, and
    # confirm the identical call then succeeds.
    iam = ctx.client("iam")
    restore_policy_name = ctx.unique_name("sim2real-cfa-restore-")
    iam.put_role_policy(
        RoleName=role_without_name,
        PolicyName=restore_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "apigateway:GET", "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_without_name, PolicyName=restore_policy_name))

    restored = _poll_until_ok(ctx, fn_without, timeout_s=45, interval_s=3)
    assert "error" not in restored, f"expected success after granting apigateway:GET, got: {restored}"
    assert api_name in restored["names"], f"expected {api_name!r} in {restored['names']} after granting permission"


def _zip_code(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx, statements: list[dict[str, Any]]) -> tuple[str, str]:
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAGS_KV)
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
    return role_name, role_arn


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
                Tags=_TAGS,
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


def _poll_until_ok(ctx, function_name: str, timeout_s: float, interval_s: float) -> dict[str, Any]:
    last: dict[str, Any] = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        last = _invoke(ctx, function_name, {})
        if "error" not in last:
            return last
        time.sleep(interval_s)
    return last


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
