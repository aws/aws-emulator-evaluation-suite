"""authorizer-ttl-zero-disables-caching."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "authorizer-ttl-zero-disables-caching"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]

_LAMBDA_CODE = (
    "def handler(event, context):\n"
    "    return {\n"
    "        'principalId': 'sim2real-test-user',\n"
    "        'policyDocument': {\n"
    "            'Version': '2012-10-17',\n"
    "            'Statement': [\n"
    "                {'Action': 'execute-api:Invoke', 'Effect': 'Allow', 'Resource': event.get('methodArn', '*')}\n"
    "            ],\n"
    "        },\n"
    "    }\n"
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """With authorizerResultTtlInSeconds=0, two calls through the deployed stage with the identical
    identity header each invoke the TOKEN Lambda authorizer (two REPORT lines in its log group)."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    apigw = ctx.client("apigateway")
    logs = ctx.client("logs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-authrole-")
    trust_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, policy_arn))

    zip_bytes = _zip_lambda_code(_LAMBDA_CODE)
    function_name = ctx.unique_name("sim2real-authfn-")
    ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
    lambda_arn = _create_function_with_retry(lam, function_name, role_arn, zip_bytes, CHECK)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    authorizer_id = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-authz-"),
        type="TOKEN",
        authorizerUri=f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{lambda_arn}/invocations",
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=0,
    )["id"]

    source_arn = f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/authorizers/{authorizer_id}"
    lam.add_permission(
        FunctionName=function_name, StatementId="sim2real-apigw-invoke",
        Action="lambda:InvokeFunction", Principal="apigateway.amazonaws.com", SourceArn=source_arn,
    )

    root_id = _root_resource_id(apigw, api_id)
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="secure")["id"]
    apigw.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET",
        authorizationType="CUSTOM", authorizerId=authorizer_id,
    )
    apigw.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200", responseTemplates={}
    )
    apigw.create_deployment(restApiId=api_id, stageName="test")

    url = f"{ctx.rest_api_url(api_id, 'test')}/secure"
    headers = {"Authorization": "sim2real-allow-token"}

    start_time_ms = int(time.time() * 1000)
    status1 = _wait_http_ok(url, headers, timeout_s=90.0, interval_s=3.0)
    assert status1 == 200, f"first authorized call did not reach the integration, got HTTP {status1}"
    status2, _ = _http_get(url, headers)
    assert status2 == 200, f"second authorized call did not reach the integration, got HTTP {status2}"

    log_group = f"/aws/lambda/{function_name}"
    invocation_count = _wait_for_report_count(logs, log_group, start_time_ms, expected=2, timeout_s=90.0)
    assert invocation_count == 2, (
        f"expected exactly 2 Lambda authorizer invocations with TTL=0 (no caching), saw {invocation_count}"
    )


def _root_resource_id(apigw: Any, api_id: str) -> str:
    for item in apigw.get_resources(restApiId=api_id)["items"]:
        if item["path"] == "/":
            return item["id"]
    raise AssertionError("root resource not found")


def _zip_lambda_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_function_with_retry(
    lam: Any, function_name: str, role_arn: str, zip_bytes: bytes, check_tag: str,
    timeout_s: float = 90.0, interval_s: float = 5.0,
) -> str:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=function_name, Runtime="python3.12", Role=role_arn,
                Handler="lambda_function.handler", Code={"ZipFile": zip_bytes}, Timeout=10, Publish=True,
                Tags={"sim2real": check_tag},
            )
            return resp["FunctionArn"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"lambda execution role never propagated for CreateFunction: {last_err}")


def _delete_role(iam: Any, role_name: str, policy_arn: str) -> None:
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _http_get(url: str, headers: dict[str, str], timeout: float = 15.0) -> tuple[int, str]:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode("utf-8", "replace")


def _wait_http_ok(url: str, headers: dict[str, str], timeout_s: float, interval_s: float) -> int:
    deadline = time.monotonic() + timeout_s
    status = -1
    while time.monotonic() < deadline:
        status, _body = _http_get(url, headers)
        if status == 200:
            return status
        time.sleep(interval_s)
    return status


def _wait_for_report_count(
    logs: Any, log_group: str, start_time_ms: int, expected: int, timeout_s: float, interval_s: float = 5.0
) -> int:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    count = 0
    while time.monotonic() < deadline:
        try:
            events = logs.filter_log_events(
                logGroupName=log_group, startTime=start_time_ms, filterPattern='"REPORT RequestId"'
            )["events"]
            count = len(events)
            if count >= expected:
                return count
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(interval_s)
    return count


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
