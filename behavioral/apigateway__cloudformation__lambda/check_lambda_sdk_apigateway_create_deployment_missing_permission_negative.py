"""lambda-sdk-apigateway-create-deployment-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sdk-apigateway-create-deployment-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "cloudformation", "lambda"]

_HANDLER_CODE = """
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    apig = boto3.client("apigateway")
    try:
        resp = apig.create_deployment(restApiId=event["api_id"], stageName=event["stage_name"])
    except ClientError as exc:
        return {"error": exc.response["Error"]["Code"]}
    return {"deployment_id": resp["id"]}
"""


@tags(
    "axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e",
    "concern:negative-classes", "dp:api", "plane:data",
)
def run(ctx) -> None:
    """A Lambda role without apigateway:POST on deployments is refused CreateDeployment and the API keeps zero
    deployments; with the grant added to the same role the identical call succeeds and the deployment lands."""
    api_with, root_with = _setup_mock_api(ctx)
    api_without, _ = _setup_mock_api(ctx)

    role_with, role_with_arn = _create_lambda_role(
        ctx, [{"Effect": "Allow", "Action": "apigateway:POST", "Resource": "*"}]
    )
    fn_with = _create_function(ctx, role_with_arn, _HANDLER_CODE)

    role_without, role_without_arn = _create_lambda_role(ctx, [])
    fn_without = _create_function(ctx, role_without_arn, _HANDLER_CODE)

    control = _invoke(ctx, fn_with, {"api_id": api_with, "stage_name": "prod"})
    assert "deployment_id" in control, f"positive control unexpectedly failed: {control}"

    apig = ctx.client("apigateway")
    deployed = apig.get_deployments(restApiId=api_with)["items"]
    assert len(deployed) == 1, f"expected exactly one deployment on control API, got {deployed}"

    denied = _invoke(ctx, fn_without, {"api_id": api_without, "stage_name": "prod"})
    assert denied.get("error") == "AccessDeniedException", f"unexpected result: {denied}"
    assert "deployment_id" not in denied, f"denied call still returned a deployment id: {denied}"

    not_deployed = apig.get_deployments(restApiId=api_without)["items"]
    assert not_deployed == [], f"expected zero deployments on denied API, got {not_deployed}"

    # Restore: grant the exact permission on the SAME role and demand the identical call now
    # succeeds, with the deployment actually landing (effect present, not merely "no error").
    iam = ctx.client("iam")
    restore_policy = ctx.unique_name("sim2real-cfa-policy-restore-")
    iam.put_role_policy(
        RoleName=role_without,
        PolicyName=restore_policy,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "apigateway:POST", "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_without, PolicyName=restore_policy))

    granted = _poll_until_deployed(ctx, fn_without, {"api_id": api_without, "stage_name": "prod"})
    assert "deployment_id" in granted, f"expected success after granting apigateway:POST, got: {granted}"

    now_deployed = apig.get_deployments(restApiId=api_without)["items"]
    assert any(d["id"] == granted["deployment_id"] for d in now_deployed), (
        f"expected the granted deployment {granted['deployment_id']} to appear, got {now_deployed}"
    )


def _setup_mock_api(ctx) -> tuple[str, str]:
    apig = ctx.client("apigateway")
    api_name = ctx.unique_name("sim2real-cfa-api-")
    api_id = apig.create_rest_api(name=api_name, tags={"sim2real-check": CHECK})["id"]
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
                Tags={"sim2real-check": CHECK},
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


def _poll_until_deployed(
    ctx, function_name: str, payload: dict[str, Any], timeout_s: float = 45.0, interval_s: float = 3.0
) -> dict[str, Any]:
    """IAM policy changes are eventually consistent, so retry the identical call until the
    freshly-granted permission takes effect."""
    last: dict[str, Any] = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        last = _invoke(ctx, function_name, payload)
        if "deployment_id" in last:
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
