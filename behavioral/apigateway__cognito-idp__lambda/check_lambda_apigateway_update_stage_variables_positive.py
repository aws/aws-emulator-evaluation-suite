"""lambda-apigateway-update-stage-variables-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-apigateway-update-stage-variables-positive"
GROUP = "sdk-call"
SERVICES = ["apigateway", "cognito-idp", "lambda"]


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda whose role has apigateway:PATCH can update a stage variable, observable via GetStage."""
    api_id, root_resource_id = _create_rest_api_with_root(ctx)
    _add_mock_method(ctx, api_id, root_resource_id)

    apigw = ctx.client("apigateway")
    stage_name = "test"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)

    statements = [
        {
            "Effect": "Allow",
            "Action": "apigateway:PATCH",
            "Resource": f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}/stages/{stage_name}",
        }
    ]
    _role_name, role_arn = _create_lambda_role(ctx, statements)

    code = (
        "import boto3\n"
        "def handler(event, context):\n"
        "    client = boto3.client('apigateway')\n"
        "    try:\n"
        f"        resp = client.update_stage(\n"
        f"            restApiId={api_id!r},\n"
        f"            stageName={stage_name!r},\n"
        "            patchOperations=[{'op': 'replace', 'path': '/variables/myVar', 'value': 'myValue'}],\n"
        "        )\n"
        "        return {'ok': True, 'variables': resp.get('variables', {})}\n"
        "    except Exception as exc:\n"
        "        code = getattr(exc, 'response', {}).get('Error', {}).get('Code')\n"
        "        return {'ok': False, 'error_code': code}\n"
    )
    function_name = _create_function(ctx, role_arn, code)

    body = _invoke(ctx, function_name)
    assert body["ok"] is True, f"lambda-triggered UpdateStage failed unexpectedly: {body}"
    assert body["variables"].get("myVar") == "myValue", (
        f"expected myVar=myValue in the lambda's own UpdateStage response, got {body['variables']}"
    )

    # Verify the change actually persisted server-side, independent of the Lambda's own response.
    stage = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert stage.get("variables", {}).get("myVar") == "myValue", stage


_ROLE_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


def _managed_tags() -> dict[str, str]:
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _zip_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_rest_api_with_root(ctx) -> tuple[str, str]:
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-behav-api-")
    api = apigw.create_rest_api(
        name=name, endpointConfiguration={"types": ["REGIONAL"]}, tags=_managed_tags()
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    return api_id, root_id


def _add_mock_method(ctx, api_id: str, resource_id: str, http_method: str = "GET") -> None:
    apigw = ctx.client("apigateway")
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod=http_method, authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200"
    )


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
        Tags=[{"Key": k, "Value": v} for k, v in _managed_tags().items()],
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
                Tags=_managed_tags(),
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
