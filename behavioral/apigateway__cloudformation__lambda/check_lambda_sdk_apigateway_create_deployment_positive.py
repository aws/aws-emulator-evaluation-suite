"""lambda-sdk-apigateway-create-deployment-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sdk-apigateway-create-deployment-positive"
GROUP = "sdk-call"
SERVICES = ["apigateway", "cloudformation", "lambda"]

_HANDLER_CODE = """
import boto3

def handler(event, context):
    apig = boto3.client("apigateway")
    resp = apig.create_deployment(restApiId=event["api_id"], stageName=event["stage_name"])
    return {"deployment_id": resp["id"]}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda's SDK CreateDeployment returns the id GetStage then reports for the stage.

    TestInvokeMethod on the method (not the deployed stage) returns the MOCK integration body.
    """
    api_id, root_id = _setup_mock_api(ctx)
    stage_name = "prod"

    role_arn = _create_lambda_role(
        ctx, [{"Effect": "Allow", "Action": "apigateway:POST", "Resource": "*"}]
    )
    fn_name = _create_function(ctx, role_arn, _HANDLER_CODE)

    result = _invoke(ctx, fn_name, {"api_id": api_id, "stage_name": stage_name})
    deployment_id = result.get("deployment_id")
    assert deployment_id, f"lambda did not return a deployment id: {result}"

    apig = ctx.client("apigateway")
    stage = apig.get_stage(restApiId=api_id, stageName=stage_name)
    assert stage["deploymentId"] == deployment_id, (
        f"stage deploymentId {stage['deploymentId']} != created deployment {deployment_id}"
    )

    invoked = apig.test_invoke_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", pathWithQueryString="/"
    )
    assert invoked["status"] == 200, f"unexpected invoke status: {invoked}"
    assert "ok-from-mock" in invoked["body"], f"unexpected invoke body: {invoked['body']}"


def _setup_mock_api(ctx) -> tuple[str, str]:
    apig = ctx.client("apigateway")
    api_name = ctx.unique_name("sim2real-cfa-api-")
    api_id = apig.create_rest_api(name=api_name, tags={"sim2real:managed": "true"})["id"]
    ctx.on_cleanup(lambda: apig.delete_rest_api(restApiId=api_id))

    resources = apig.get_resources(restApiId=api_id)["items"]
    root_id = next(r["id"] for r in resources if r["path"] == "/")

    apig.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apig.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apig.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apig.put_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": '{"message": "ok-from-mock"}'},
    )
    return api_id, root_id


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
