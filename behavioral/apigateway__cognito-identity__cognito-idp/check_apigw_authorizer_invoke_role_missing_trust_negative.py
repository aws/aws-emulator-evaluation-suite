"""apigw-authorizer-invoke-role-missing-trust-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "apigw-authorizer-invoke-role-missing-trust-negative"
GROUP = "overly-permissive"
SERVICES = ["apigateway", "cognito-identity", "cognito-idp"]

_AUTHORIZER_CODE = """
def handler(event, context):
    token = event.get("authorizationToken", "")
    effect = "Allow" if token == "allow-me" else "Deny"
    return {
        "principalId": "user",
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
    }
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An authorizer role not trusting apigateway makes TestInvokeAuthorizer return 500 with no policy.
    An identical role trusting apigateway on the same Lambda and API succeeds with an Allow policy.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    apigw = ctx.client("apigateway")

    lambda_role_arn = _create_lambda_exec_role(ctx, iam)
    func_name = ctx.unique_name("sim2real-behav-authzfn-")
    zip_bytes = _zip_lambda_code(_AUTHORIZER_CODE)
    fn = _create_function_with_retry(ctx, lam, func_name, lambda_role_arn, zip_bytes)
    function_arn = fn["FunctionArn"]

    # Broken: trusts an unrelated service principal instead of apigateway.amazonaws.com.
    bad_role_arn = _create_authorizer_role(
        ctx, iam, "states.amazonaws.com", allow_invoke_arn=function_arn
    )
    # Control: identical invoke-permission policy, only the trust principal differs.
    good_role_arn = _create_authorizer_role(
        ctx, iam, "apigateway.amazonaws.com", allow_invoke_arn=function_arn
    )

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    bad_authorizer_id = _create_token_authorizer(
        ctx, apigw, api_id, "authz-bad-trust", function_arn, bad_role_arn
    )
    good_authorizer_id = _create_token_authorizer(
        ctx, apigw, api_id, "authz-good-trust", function_arn, good_role_arn
    )

    bad_result = apigw.test_invoke_authorizer(
        restApiId=api_id, authorizerId=bad_authorizer_id, headers={"Authorization": "allow-me"}
    )
    assert bad_result["clientStatus"] == 500, f"expected 500 (role not assumable), got {bad_result}"
    assert not bad_result.get("policy"), "no policy should have been produced: Lambda never ran"

    good_result = _poll_test_invoke(ctx, apigw, api_id, good_authorizer_id, "allow-me")
    assert good_result["clientStatus"] == 0, f"control authorizer should succeed, got {good_result}"
    good_policy = json.loads(good_result["policy"])
    good_effect = good_policy["Statement"][0]["Effect"]
    assert good_effect == "Allow", f"expected control policy Effect Allow, got {good_effect}"


def _zip_lambda_code(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_lambda_exec_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-behav-lambdaexec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    # Cleanups run LIFO, so the detach runs before delete_role (which would otherwise
    # fail with DeleteConflict).
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Arn"]


def _create_function_with_retry(ctx, lam, name, role_arn, zip_bytes, timeout_s=45.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=10,
                Tags={"sim2real": CHECK},
            )
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            return resp
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(2)
    raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")


def _create_authorizer_role(ctx, iam, trust_service, allow_invoke_arn=None) -> str:
    role_name = ctx.unique_name("sim2real-behav-authzrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if allow_invoke_arn:
        policy_name = "invoke-lambda"
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": allow_invoke_arn}],
        }
        iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _create_token_authorizer(ctx, apigw, api_id, name, function_arn, role_arn) -> str:
    uri = f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{function_arn}/invocations"
    resp = apigw.create_authorizer(
        restApiId=api_id,
        name=name,
        type="TOKEN",
        authorizerUri=uri,
        authorizerCredentials=role_arn,
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=0,
    )
    ctx.on_cleanup(lambda: apigw.delete_authorizer(restApiId=api_id, authorizerId=resp["id"]))
    return resp["id"]


def _poll_test_invoke(ctx, apigw, api_id, authorizer_id, token, timeout_s=45.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = apigw.test_invoke_authorizer(
            restApiId=api_id, authorizerId=authorizer_id, headers={"Authorization": token}
        )
        if last["clientStatus"] == 0:
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
