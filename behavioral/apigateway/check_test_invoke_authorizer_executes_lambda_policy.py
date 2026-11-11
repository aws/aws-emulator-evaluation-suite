"""test-invoke-authorizer-executes-lambda-policy."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-invoke-authorizer-executes-lambda-policy"
GROUP = "server-side"
SERVICES = ["apigateway"]

_LAMBDA_SRC = """
def handler(event, context):
    token = event.get("authorizationToken", "")
    effect = "Allow" if token == "allow-me" else "Deny"
    return {
        "principalId": "sim2real-authz-user",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {"Action": "execute-api:Invoke", "Effect": effect, "Resource": event.get("methodArn", "*")}
            ],
        },
    }
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestInvokeAuthorizer synchronously executes the real Lambda authorizer and returns its policy,
    without mutating the stored authorizer configuration."""
    apigw = ctx.client("apigateway")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    role_arn, role_name = _create_lambda_role(ctx, iam)
    function_name = ctx.unique_name("sim2real-authz-fn-")
    function_arn = _create_lambda_function(ctx, lam, function_name, role_arn)

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-authz-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    region = ctx.region
    account_id = sts.get_caller_identity()["Account"]
    authorizer_uri = (
        f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/{function_arn}/invocations"
    )

    authorizer = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-authorizer-"),
        type="TOKEN",
        authorizerUri=authorizer_uri,
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=0,
    )
    authorizer_id = authorizer["id"]
    ctx.on_cleanup(lambda: apigw.delete_authorizer(restApiId=api_id, authorizerId=authorizer_id))

    lam.add_permission(
        FunctionName=function_name,
        StatementId="sim2real-apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{region}:{account_id}:{api_id}/authorizers/{authorizer_id}",
    )

    before = apigw.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)

    allow_resp = apigw.test_invoke_authorizer(
        restApiId=api_id, authorizerId=authorizer_id, headers={"Authorization": "allow-me"}
    )
    allow_policy = json.loads(allow_resp["policy"])
    assert allow_policy["Statement"][0]["Effect"] == "Allow", allow_policy
    assert allow_resp["principalId"] == "sim2real-authz-user", (
        f"expected the Lambda-computed principalId 'sim2real-authz-user', got {allow_resp['principalId']!r}"
    )

    deny_resp = apigw.test_invoke_authorizer(
        restApiId=api_id, authorizerId=authorizer_id, headers={"Authorization": "wrong-token"}
    )
    deny_policy = json.loads(deny_resp["policy"])
    assert deny_policy["Statement"][0]["Effect"] == "Deny", deny_policy

    after = apigw.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    # TestInvokeAuthorizer must not mutate the stored authorizer.
    for field in ("name", "type", "authorizerUri", "identitySource", "authorizerResultTtlInSeconds"):
        assert before.get(field) == after.get(field), f"authorizer field {field} changed after test-invoke"


def _create_lambda_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-authz-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role["Role"]["Arn"], role_name


def _create_lambda_function(ctx, lam, function_name, role_arn):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", _LAMBDA_SRC)
    zip_bytes = buf.getvalue()

    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=10,
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] in ("InvalidParameterValueException",):
                last_err = e
                time.sleep(3)
                continue
            raise
    else:
        raise AssertionError(f"lambda role never became usable: {last_err}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))

    # Wait for the function to leave Pending state before anything tries to invoke it.
    state_deadline = time.monotonic() + 60.0
    last_state = None
    while time.monotonic() < state_deadline:
        cfg = lam.get_function_configuration(FunctionName=function_name)
        last_state = cfg.get("State")
        if last_state == "Active":
            break
        time.sleep(2)
    else:
        raise AssertionError(f"lambda function {function_name} never became Active, last state: {last_state}")

    return resp["FunctionArn"]


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
