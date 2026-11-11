"""e2e-custom-authorizer-protected-method-flow."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "e2e-custom-authorizer-protected-method-flow"
GROUP = "e2e"
SERVICES = ["apigateway"]

_LAMBDA_CODE = """
def handler(event, context):
    token = event.get("authorizationToken", "")
    effect = "Allow" if token == "allow-me" else "Deny"
    return {
        "principalId": "sim2real-user",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": event["methodArn"],
                }
            ],
        },
    }
"""


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A TOKEN Lambda authorizer: TestInvokeMethod with the allowed token returns the mock response,
    and the deployed endpoint denies a tokenless request (401/403) and admits one with the token."""
    iam = ctx.client("iam")
    lambda_client = ctx.client("lambda")
    sts = ctx.client("sts")
    apigw = ctx.client("apigateway")
    logs = ctx.client("logs")

    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-authz-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))

    basic_exec_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_exec_policy_arn)
    ctx.on_cleanup(lambda: _safe_detach_role_policy(iam, role_name, basic_exec_policy_arn))

    func_name = ctx.unique_name("sim2real-authz-fn-")
    zip_bytes = _build_zip("index.py", _LAMBDA_CODE)
    fn = _create_function_with_retry(lambda_client, func_name, role_arn, zip_bytes, tags={"sim2real": CHECK})
    # Lambda creates /aws/lambda/<name> on the first invocation; it outlives the function.
    ctx.on_cleanup(lambda: _safe_delete_log_group(logs, f"/aws/lambda/{func_name}"))
    ctx.on_cleanup(lambda: _safe_delete_function(lambda_client, func_name))

    _poll_until(
        lambda: lambda_client.get_function(FunctionName=func_name)["Configuration"]["State"],
        lambda state: state == "Active",
        timeout_s=60.0,
    )

    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-authzapi-"), tags={"sim2real": CHECK})
    api_id = api["id"]
    ctx.on_cleanup(lambda: _safe_delete_rest_api(apigw, api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="secure")
    resource_id = resource["id"]

    authorizer = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-authorizer-"),
        type="TOKEN",
        authorizerUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{fn['FunctionArn']}/invocations"
        ),
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=0,
    )
    authorizer_id = authorizer["id"]
    ctx.on_cleanup(lambda: _safe_delete_authorizer(apigw, api_id, authorizer_id))

    lambda_client.add_permission(
        FunctionName=func_name,
        StatementId="sim2real-apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/authorizers/{authorizer_id}",
    )

    apigw.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="CUSTOM",
        authorizerId=authorizer_id,
    )
    # DeleteAuthorizer refuses an authorizer a method still references, so the method goes first.
    ctx.on_cleanup(lambda: _safe_delete_method(apigw, api_id, resource_id))
    apigw.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": '{"message": "secured-ok"}'},
    )

    # Control-plane test-invoke path: with a valid identity-source header, API
    # Gateway's test-invoke feature exercises the authorizer + mock integration
    # and returns a successful simulated response.
    allowed = apigw.test_invoke_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        headers={"Authorization": "allow-me"},
    )
    assert allowed["status"] == 200, f"expected 200 once authorized, got {allowed['status']}"
    body = json.loads(allowed["body"])
    assert body == {"message": "secured-ok"}, f"unexpected body after authorization: {body!r}"

    # Deploy so we can observe the REAL data-plane consequence of the authorizer
    # decision, which TestInvokeMethod does not faithfully reproduce for denials.
    deployment = apigw.create_deployment(restApiId=api_id)
    stage_name = "prod"
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment["id"])

    url = f"{ctx.rest_api_url(api_id, stage_name)}/secure"

    # Without an Authorization header API Gateway rejects the request before the integration;
    # the deployed endpoint can lag the deployment by a few seconds, so poll for the non-200 outcome.
    denied_status, denied_body = _poll_status(url, {}, expect_non_200=True, timeout_s=60.0)
    assert denied_status in (401, 403), (
        f"expected the real endpoint to deny (401/403) with no identity source, got {denied_status}"
    )
    assert denied_body.decode("utf-8", "replace") == '{"message":"Unauthorized"}', (
        f"expected the default 401 Unauthorized body, got status={denied_status} body={denied_body!r}"
    )

    # Authorization header with the allowed token: the real Lambda authorizer
    # grants access end-to-end, and the mock integration actually runs.
    allowed_status, allowed_body = _get(url, {"Authorization": "allow-me"})
    assert allowed_status == 200, f"expected 200 on the real endpoint once authorized, got {allowed_status}"
    assert json.loads(allowed_body) == {"message": "secured-ok"}, (
        f"expected the mock integration's response body once authorized, got {allowed_body!r}"
    )


def _get(url: str, headers: dict[str, str]) -> tuple[int | None, bytes]:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except urllib.error.URLError:
        return None, b""


def _poll_status(
    url: str, headers: dict[str, str], *, expect_non_200: bool, timeout_s: float
) -> tuple[int | None, bytes]:
    deadline = time.monotonic() + timeout_s
    last_status, last_body = None, b""
    while time.monotonic() < deadline:
        last_status, last_body = _get(url, headers)
        if expect_non_200 and last_status is not None and last_status != 200:
            return last_status, last_body
        if not expect_non_200 and last_status == 200:
            return last_status, last_body
        time.sleep(3.0)
    return last_status, last_body


def _build_zip(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _create_function_with_retry(
    lambda_client, func_name: str, role_arn: str, zip_bytes: bytes, tags: dict[str, str] | None = None
) -> dict[str, Any]:
    last_exc: Exception | None = None
    for _ in range(10):
        try:
            return lambda_client.create_function(
                FunctionName=func_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=10,
                Tags=tags or {},
            )
        except lambda_client.exceptions.InvalidParameterValueException as exc:
            # The IAM role's trust policy may not have propagated to Lambda yet.
            last_exc = exc
            time.sleep(3.0)
    raise AssertionError(f"create_function never succeeded after role propagation retries: {last_exc}")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s; last value={last!r}")


def _safe_delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except iam.exceptions.NoSuchEntityException:
        pass


def _safe_detach_role_policy(iam, role_name: str, policy_arn: str) -> None:
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except iam.exceptions.NoSuchEntityException:
        pass


def _safe_delete_function(lambda_client, func_name: str) -> None:
    try:
        lambda_client.delete_function(FunctionName=func_name)
    except lambda_client.exceptions.ResourceNotFoundException:
        pass


def _safe_delete_log_group(logs, name: str) -> None:
    try:
        logs.delete_log_group(logGroupName=name)
    except logs.exceptions.ResourceNotFoundException:
        pass


def _safe_delete_method(apigw, api_id: str, resource_id: str) -> None:
    try:
        apigw.delete_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    except apigw.exceptions.NotFoundException:
        pass


def _safe_delete_authorizer(apigw, api_id: str, authorizer_id: str) -> None:
    try:
        apigw.delete_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    except apigw.exceptions.NotFoundException:
        pass


def _safe_delete_rest_api(apigw, api_id: str) -> None:
    try:
        apigw.delete_rest_api(restApiId=api_id)
    except apigw.exceptions.NotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

