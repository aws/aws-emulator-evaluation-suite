"""lambda-apigateway-get-rest-apis-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-apigateway-get-rest-apis-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "cognito-idp", "lambda"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A Lambda whose role lacks apigateway:GET gets AccessDeniedException calling GetRestApis; granting it fixes it."""
    api_id = _create_rest_api(ctx)
    role_name, role_arn = _create_lambda_role(ctx, inline_statements=None)

    code = (
        "import boto3\n"
        "def handler(event, context):\n"
        "    client = boto3.client('apigateway')\n"
        "    try:\n"
        "        resp = client.get_rest_apis(limit=500)\n"
        "        ids = [item['id'] for item in resp.get('items', [])]\n"
        "        return {'ok': True, 'ids': ids}\n"
        "    except Exception as exc:\n"
        "        code = getattr(exc, 'response', {}).get('Error', {}).get('Code')\n"
        "        return {'ok': False, 'error_code': code}\n"
    )
    function_name = _create_function(ctx, role_arn, code)

    denied = _invoke(ctx, function_name)
    assert denied["ok"] is False, f"expected the call to be denied without apigateway:GET, got: {denied}"
    assert denied["error_code"] == "AccessDeniedException", denied

    # Positive control: grant the exact permission on the SAME role/function and confirm the
    # identical call succeeds and observes the REST API created above (effect present).
    iam = ctx.client("iam")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="apigateway-access",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "apigateway:GET",
                        "Resource": f"arn:aws:apigateway:{ctx.region}::/restapis*",
                    }
                ],
            }
        ),
    )

    granted = _poll_until_ok(ctx, function_name, timeout_s=45, interval_s=3)
    assert granted["ok"] is True, f"expected success after granting apigateway:GET, got: {granted}"
    assert api_id in granted["ids"], f"REST API {api_id} not visible even after permission granted: {granted}"


_ROLE_TRUST_POLICY = json.dumps(
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
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_rest_api(ctx) -> str:
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-behav-api-")
    api = apigw.create_rest_api(
        name=name, endpointConfiguration={"types": ["REGIONAL"]}, tags={"sim2real:managed": "true"}
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    return api_id


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_lambda_role(ctx, inline_statements: list[dict[str, Any]] | None) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_ROLE_TRUST_POLICY,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    if inline_statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="apigateway-access",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )
    return role_name, role_arn


def _create_function(ctx, role_arn: str, code: str) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    zipped = _zip_code(code)
    last_err: Exception | None = None
    deadline = time.monotonic() + 90
    resp = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zipped},
                Timeout=30,
                Publish=True,
                Tags={"sim2real:managed": "true"},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"lambda never accepted the execution role: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    waiter = lam.get_waiter("function_active_v2")
    waiter.wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return name


def _invoke(ctx, function_name: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=function_name, Payload=json.dumps(payload or {}).encode("utf-8"))
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation errored: {body}")
    return body


def _poll_until_ok(ctx, function_name: str, timeout_s: float, interval_s: float) -> dict[str, Any]:
    last: dict[str, Any] = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        last = _invoke(ctx, function_name)
        if last.get("ok"):
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
