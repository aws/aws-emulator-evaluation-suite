"""test-invoke-authorizer-returns-policy-and-claims."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "test-invoke-authorizer-returns-policy-and-claims"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestInvokeAuthorizer runs the Lambda REQUEST authorizer and returns its policy and principal:
    `claims` is absent (Cognito-only), the Lambda's context reaches the caller only via `log`
    (a per-run claim proves the call), and the policy Resource is the run's test-invoke method ARN."""
    iam = ctx.client("iam")
    lambda_client = ctx.client("lambda")
    apigw = ctx.client("apigateway")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-authzrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        )
    )

    function_name = ctx.unique_name("sim2real-authzfn-")
    claim_value = ctx.unique_name("sim2real-claim-")
    zip_bytes = _build_authorizer_zip(claim_value)
    ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
    function_arn = _create_function_with_retry(lambda_client, function_name, role_arn, zip_bytes)
    ctx.on_cleanup(lambda: lambda_client.delete_function(FunctionName=function_name))

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-testauthz-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    authorizer_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{function_arn}/invocations"
    )
    authorizer_id = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-authorizer-"),
        type="REQUEST",
        authorizerUri=authorizer_uri,
        identitySource="method.request.header.Authorization",
    )["id"]

    lambda_client.add_permission(
        FunctionName=function_name,
        StatementId="apigw-test-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/authorizers/{authorizer_id}",
    )

    resp = _test_invoke_with_retry(
        apigw, api_id, authorizer_id, headers={"Authorization": "allow-me"}
    )

    assert resp["clientStatus"] == 0, f"authorizer invocation was not treated as successful: {resp}"
    assert resp["principalId"] == "sim2real-test-user", (
        f"expected the Lambda-computed principalId to surface unchanged, got {resp!r}"
    )
    policy = json.loads(resp["policy"])
    assert policy["Statement"][0]["Effect"] == "Allow", f"expected an Allow statement, got {policy!r}"
    assert policy["Statement"][0]["Action"] == "execute-api:Invoke", (
        f"expected the Lambda-authored action to survive unchanged, got {policy!r}"
    )
    # API Gateway synthesizes the test-invoke method ARN itself (it is what the Lambda received
    # as event['methodArn'] and echoed into the policy) -- it embeds this run's real api_id, so a
    # canned response cannot reproduce it.
    expected_resource = f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/ESTestInvoke-stage/GET/"
    assert policy["Statement"][0]["Resource"] == expected_resource, (
        f"expected the synthesized test-invoke method ARN {expected_resource!r}, "
        f"got {policy['Statement'][0].get('Resource')!r}"
    )

    # `claims` is exclusively sourced from a Cognito User Pool authorizer; for this Lambda-backed
    # REQUEST authorizer it must be absent from the response entirely, not present-but-empty --
    # an emulator that (wrongly) populates it from the Lambda's `context` output would be caught.
    assert "claims" not in resp, f"claims must be absent for a non-Cognito authorizer, got {resp['claims']!r}"

    # The Lambda's `context` output reaches the caller only via the execution log (`authorization`
    # is a fixed scaffold); the per-run claim proves this invocation happened.
    assert claim_value in resp["log"], (
        f"expected the authorizer's per-run claim {claim_value!r} to appear in the execution log, "
        f"got log={resp['log']!r}"
    )


def _build_authorizer_zip(claim_value: str) -> bytes:
    source = (
        "def handler(event, context):\n"
        "    return {\n"
        "        'principalId': 'sim2real-test-user',\n"
        "        'policyDocument': {\n"
        "            'Version': '2012-10-17',\n"
        "            'Statement': [\n"
        "                {'Action': 'execute-api:Invoke', 'Effect': 'Allow', 'Resource': event['methodArn']}\n"
        "            ],\n"
        "        },\n"
        f"        'context': {{'sim2realClaim': {claim_value!r}}},\n"
        "    }\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


def _create_function_with_retry(lambda_client, function_name, role_arn, zip_bytes, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = lambda_client.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=10,
            )
            break
        except lambda_client.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(3)
    else:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_exc}")

    waiter = lambda_client.get_waiter("function_active_v2")
    waiter.wait(FunctionName=function_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return resp["FunctionArn"]


def _test_invoke_with_retry(apigw, api_id, authorizer_id, headers, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return apigw.test_invoke_authorizer(
                restApiId=api_id, authorizerId=authorizer_id, headers=headers
            )
        except apigw.exceptions.BadRequestException as exc:
            # transient: apigateway hasn't yet been granted the lambda invoke permission
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"test_invoke_authorizer never succeeded: {last_exc}")


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
