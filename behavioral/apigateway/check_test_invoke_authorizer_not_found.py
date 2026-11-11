"""test-invoke-authorizer-not-found."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-invoke-authorizer-not-found"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']

_TOKEN_AUTHORIZER_LAMBDA_SOURCE = """
def handler(event, context):
    return {
        "principalId": "sim2real-behav-user",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": "Allow",
                    "Resource": event.get("methodArn", "*"),
                }
            ],
        },
    }
"""


def _client_error(fn):
    """The botocore Error dict of the ClientError fn raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id


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
    """Create a Lambda execution role with AWSLambdaBasicExecutionRole attached; return its ARN."""
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
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", source)
    code = buf.getvalue()
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
        assert last_exc is not None, "create_function retry loop exited with no response and no error"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TestInvokeAuthorizer with a nonexistent authorizerId fails NotFoundException, while a real
    Lambda TOKEN authorizer on the same RestApi succeeds with clientStatus 0 (positive control)."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)

    role_arn = _create_lambda_execution_role(ctx)
    function_arn = _create_lambda_function(ctx, _TOKEN_AUTHORIZER_LAMBDA_SOURCE, role_arn)
    _allow_apigateway_invoke(ctx, function_arn)
    authorizer_id = ag.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("tokenauth-"),
        type="TOKEN",
        authorizerUri=_lambda_integration_uri(ctx, function_arn),
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=0,
    )["id"]

    control_resp = ag.test_invoke_authorizer(
        restApiId=api_id, authorizerId=authorizer_id, headers={"Authorization": "let-me-in"}
    )
    assert control_resp.get("clientStatus") == 0, (
        f"positive control: TestInvokeAuthorizer against a REAL authorizerId on this RestApi "
        f"must succeed (clientStatus 0), got {control_resp.get('clientStatus')!r} -- otherwise "
        f"the not-found rejection below cannot be distinguished from every call being rejected"
    )

    err = _client_error(
        lambda: ag.test_invoke_authorizer(restApiId=api_id, authorizerId="sim2realNOTFOUND")
    )
    assert err.get("Code") == "NotFoundException", (
        f"expected NotFoundException for a nonexistent authorizerId, got {err.get('Code')!r}"
    )
    assert err.get("Message") == "Invalid Authorizer identifier specified", (
        f"expected the exact unknown-authorizer refusal message, got {err.get('Message')!r}"
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
