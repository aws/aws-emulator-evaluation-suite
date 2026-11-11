"""flush-stage-authorizers-cache-bypasses-ttl."""
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

CHECK = "flush-stage-authorizers-cache-bypasses-ttl"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]

_AUTHZ_SRC = '''
import json

_STATE = {"count": 0}

def handler(event, context):
    _STATE["count"] += 1
    token = event.get("authorizationToken", "")
    effect = "Allow" if token == "let-me-in" else "Deny"
    return {
        "principalId": "allowed-user",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {"Action": "execute-api:Invoke", "Effect": effect, "Resource": event["methodArn"]}
            ],
        },
        "context": {"count": str(_STATE["count"])},
    }
'''


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """FlushStageAuthorizersCache forces the next request on a stage to re-invoke the
    Lambda authorizer immediately, even though the authorizer's TTL window is far from
    expiring."""
    apigw = ctx.client("apigateway")

    role_arn = _create_lambda_role(ctx)
    fn_name, fn_arn = _create_authorizer_function(ctx, role_arn)

    rest_api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-flushauthz-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=rest_api_id))
    root_id = apigw.get_resources(restApiId=rest_api_id)["items"][0]["id"]

    authorizer_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fn_arn}/invocations"
    )
    authorizer_id = apigw.create_authorizer(
        restApiId=rest_api_id,
        name=ctx.unique_name("sim2real-flushauthz-"),
        type="TOKEN",
        authorizerUri=authorizer_uri,
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=300,  # deliberately long: only a flush should bypass it
    )["id"]

    _allow_apigateway_invoke(ctx, fn_name, rest_api_id, authorizer_id)

    resource_id = apigw.create_resource(
        restApiId=rest_api_id, parentId=root_id, pathPart="authtest"
    )["id"]
    apigw.put_method(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="CUSTOM",
        authorizerId=authorizer_id,
    )
    apigw.put_integration(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(
        restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration_response(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": '{"count": "$context.authorizer.count"}'},
    )
    stage_name = "test"
    apigw.create_deployment(restApiId=rest_api_id, stageName=stage_name)

    url = f"{ctx.rest_api_url(rest_api_id, stage_name)}/authtest"
    headers = {"Authorization": "let-me-in"}

    call_a = _get_json_with_retries(url, headers)
    call_b = _get_json_with_retries(url, headers)
    assert call_a["count"] == call_b["count"], (
        f"expected cached authorizer result within the 300s TTL, got {call_a} then {call_b}"
    )

    flush_resp = apigw.flush_stage_authorizers_cache(restApiId=rest_api_id, stageName=stage_name)
    assert flush_resp["ResponseMetadata"]["HTTPStatusCode"] == 202, flush_resp

    # FlushStageAuthorizersCache returning 202 means the flush was accepted, but its
    # effect on the data-plane authorizer cache is not guaranteed to be visible on the
    # very next request -- propagation across the data plane can take substantially
    # longer than a few seconds; poll (bounded, generously) rather than asserting on a
    # single immediate call or a short-lived window.
    call_c = _poll_for_fresh_invocation(url, headers, baseline_count=call_b["count"], timeout_s=120.0)
    assert int(call_c["count"]) > int(call_b["count"]), (
        f"expected FlushStageAuthorizersCache to force a fresh invocation despite the "
        f"300s TTL, got {call_b} then {call_c}"
    )


def _lambda_zip_bytes(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", source)
    return buf.getvalue()


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-apigw-flushauthz-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_authorizer_function(ctx, role_arn: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-apigw-flushauthz-")
    code = _lambda_zip_bytes(_AUTHZ_SRC)
    deadline = time.monotonic() + 60
    resp = None
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": code},
                Timeout=10,
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _wait_for_function_active(lam, fn_name)
    return fn_name, resp["FunctionArn"]


def _wait_for_function_active(lam, fn_name: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = lam.get_function(FunctionName=fn_name)["Configuration"]["State"]
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(f"lambda function {fn_name} entered Failed state")
        time.sleep(2)
    raise AssertionError(f"lambda function {fn_name} never became Active within {timeout_s}s")


def _allow_apigateway_invoke(ctx, function_name: str, rest_api_id: str, authorizer_id: str) -> None:
    lam = ctx.client("lambda")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    source_arn = f"arn:aws:execute-api:{ctx.region}:{account_id}:{rest_api_id}/authorizers/{authorizer_id}"
    lam.add_permission(
        FunctionName=function_name,
        StatementId="apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=source_arn,
    )


def _get_json_with_retries(url: str, headers: dict[str, str], timeout_s: float = 90.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"never got a successful response from {url}: {last_err}")


def _poll_for_fresh_invocation(
    url: str, headers: dict[str, str], baseline_count: str, timeout_s: float = 20.0
) -> dict[str, Any]:
    """Repeatedly call the live endpoint until the returned authorizer invocation count
    rises above baseline_count, bounded by timeout_s."""
    deadline = time.monotonic() + timeout_s
    last_result: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        last_result = _get_json_with_retries(url, headers, timeout_s=10.0)
        if int(last_result["count"]) > int(baseline_count):
            return last_result
        time.sleep(1)
    raise AssertionError(
        f"authorizer count never advanced past baseline {baseline_count} within {timeout_s}s "
        f"(last observed: {last_result})"
    )


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
