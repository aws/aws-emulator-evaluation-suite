"""lambda-apigateway-create-deployment-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-apigateway-create-deployment-positive"
GROUP = "sdk-management-call"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

_MANAGED_TAG_KEY = "sim2real:managed"


def _resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true"}


def _resource_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


HANDLER_CODE = """
import boto3

def handler(event, context):
    client = boto3.client("apigateway")
    resp = client.create_deployment(
        restApiId=event["restApiId"],
        stageName=event["stageName"],
        description="sim2real-behavioral-deploy",
    )
    return {"deploymentId": resp["id"]}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda function calls apigateway.create_deployment via boto3; the resulting
    deployment is then observable through apigateway describe calls made independently
    of the Lambda function (get_deployment, get_stage)."""
    api_id, root_id = _create_mock_rest_api(ctx)

    role_arn = _create_lambda_role(
        ctx,
        [
            {"Effect": "Allow", "Action": ["apigateway:POST", "apigateway:GET"], "Resource": "*"},
        ],
    )
    fn_name = _create_lambda_function(ctx, role_arn, HANDLER_CODE)

    stage_name = "sim2real"
    payload = _invoke(ctx, fn_name, {"restApiId": api_id, "stageName": stage_name})
    deployment_id = payload["deploymentId"]
    assert deployment_id, f"lambda-triggered create_deployment returned no deployment id: {payload}"

    apigw = ctx.client("apigateway")
    deployment = apigw.get_deployment(restApiId=api_id, deploymentId=deployment_id)
    assert deployment["id"] == deployment_id, (
        f"independent get_deployment returned id {deployment['id']!r}, expected {deployment_id!r}"
    )

    stage = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert stage["deploymentId"] == deployment_id, (
        f"stage {stage_name!r} points at deployment {stage['deploymentId']!r}, expected {deployment_id!r}"
    )


def _zip_code(filename: str, code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_mock_rest_api(ctx) -> tuple[str, str]:
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-api-")
    api = apigw.create_rest_api(name=name, tags=_resource_tags())
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": '{"message": "ok"}'},
    )
    return api_id, root_id


def _create_lambda_role(ctx, policy_statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_resource_tags_kv()
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_arn))
    if policy_statements:
        policy_name = ctx.unique_name("sim2real-lam-pol-")
        doc = {"Version": "2012-10-17", "Statement": policy_statements}
        iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(doc))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_lambda_function(ctx, role_arn: str, code: str, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-lam-fn-")
    zip_bytes = _zip_code("index.py", code)
    last_err = None
    for _ in range(15):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Tags=_resource_tags(),
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
            continue
    else:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_for_active(ctx, name)
    return name


def _wait_for_active(ctx, name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"lambda {name} never became Active")


def _invoke(ctx, name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=name, Payload=json.dumps(payload).encode())
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invoke error: {body}")
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
