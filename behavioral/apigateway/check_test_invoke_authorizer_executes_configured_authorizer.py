"""test-invoke-authorizer-executes-configured-authorizer."""
from __future__ import annotations

import io
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-invoke-authorizer-executes-configured-authorizer"
GROUP = 'invoke'
SERVICES = ['apigateway']

_TOKEN_AUTHORIZER_LAMBDA_SOURCE = """
def handler(event, context):
    token = event.get("authorizationToken", "")
    effect = "Allow" if token == "let-me-in" else "Deny"
    return {
        "principalId": "sim2real-behav-user",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": event.get("methodArn", "*"),
                }
            ],
        },
        "context": {"tokenSeen": token},
    }
"""


def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id


def _zip_lambda_source(source: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _delete_role(iam, role_name):
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


def _create_lambda_execution_role(ctx):
    """Create an IAM role trusted by lambda.amazonaws.com with the managed
    basic-execution policy attached. Returns the role ARN (teardown registered)."""
    import json
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-lambda-role-")
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
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    return role_arn


def _create_lambda_function(ctx, source, role_arn, name_prefix="sim2real-behav-authfn-", timeout=10):
    """Create a Python Lambda from inline source (handler index.handler), retrying while the
    IAM role/trust propagates. Returns the function ARN (teardown registered), waits Active."""
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name(name_prefix)
    code = _zip_lambda_source(source)
    last_exc = None
    resp = None
    for attempt in range(10):
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code},
                Timeout=timeout,
                Publish=False,
            )
            break
        except ClientError as exc:
            code_name = exc.response.get("Error", {}).get("Code")
            if code_name not in ("InvalidParameterValueException",):
                raise
            last_exc = exc
            time.sleep(3 + attempt)
    if resp is None:
        assert last_exc is not None, "create_function retry loop exited with neither a response nor an exception"
        raise last_exc
    fn_arn = resp["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active_v2").wait(
        FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 30}
    )
    return fn_arn


def _allow_apigateway_invoke(ctx, function_name_or_arn):
    """Grant apigateway.amazonaws.com permission to invoke the given Lambda."""
    ctx.client("lambda").add_permission(
        FunctionName=function_name_or_arn,
        StatementId=ctx.unique_name("invoke-"),
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
    )


def _lambda_integration_uri(ctx, function_arn):
    return (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
        f"{function_arn}/invocations"
    )


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestInvokeAuthorizer evaluates the configured Lambda TOKEN authorizer: a valid token returns
    clientStatus 0 with the Lambda's own principalId, an invalid one a Deny policy with a non-zero
    clientStatus."""
    ag = ctx.client("apigateway")
    role_arn = _create_lambda_execution_role(ctx)
    function_arn = _create_lambda_function(ctx, _TOKEN_AUTHORIZER_LAMBDA_SOURCE, role_arn)
    _allow_apigateway_invoke(ctx, function_arn)

    api_id = _create_api(ctx, ag)
    authorizer = ag.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("tokenauth-"),
        type="TOKEN",
        authorizerUri=_lambda_integration_uri(ctx, function_arn),
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=0,
    )
    authorizer_id = authorizer["id"]
    before = ag.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)

    allow_resp = ag.test_invoke_authorizer(
        restApiId=api_id, authorizerId=authorizer_id, headers={"Authorization": "let-me-in"}
    )
    assert allow_resp.get("clientStatus") == 0, (
        f"expected clientStatus 0 (authorizer succeeded/Allow) for a token the Lambda allows, "
        f"got {allow_resp.get('clientStatus')!r}"
    )
    assert allow_resp.get("principalId") == "sim2real-behav-user", (
        f"expected the Lambda-computed principalId to surface, got {allow_resp!r}"
    )
    allow_policy = allow_resp.get("policy")
    assert allow_policy and '"Effect":"Allow"' in allow_policy.replace(" ", ""), (
        f"expected an Allow statement in the returned policy, got {allow_policy!r}"
    )

    deny_resp = ag.test_invoke_authorizer(
        restApiId=api_id, authorizerId=authorizer_id, headers={"Authorization": "wrong-token"}
    )
    # clientStatus reports whether the authorizer Lambda ran (0 = success), not its decision: a Lambda
    # returning Deny still reports 0, so the decision is read from `policy`.
    assert deny_resp.get("clientStatus") == 0, (
        f"expected clientStatus 0 (the Lambda authorizer itself executed successfully, "
        f"regardless of its Allow/Deny decision), got {deny_resp.get('clientStatus')!r}"
    )
    deny_policy = deny_resp.get("policy")
    assert deny_policy and '"Effect":"Deny"' in deny_policy.replace(" ", ""), (
        f"expected a Deny statement in the returned policy for the wrong token, got {deny_policy!r}"
    )
    after = ag.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    for field in ("name", "type", "authorizerUri", "identitySource", "authorizerResultTtlInSeconds"):
        assert before.get(field) == after.get(field), (
            f"TestInvokeAuthorizer must not mutate the stored authorizer, "
            f"but {field} changed from {before.get(field)!r} to {after.get(field)!r}"
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
