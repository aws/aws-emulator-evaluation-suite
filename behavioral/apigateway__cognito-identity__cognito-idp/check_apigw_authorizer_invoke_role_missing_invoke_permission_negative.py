"""apigw-authorizer-invoke-role-missing-invoke-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "apigw-authorizer-invoke-role-missing-invoke-permission-negative"
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


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An authorizer invocation role trusted by apigateway.amazonaws.com but without lambda:InvokeFunction on the
    authorizer yields a 500 authorizer configuration error, while an identical role with the grant succeeds."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    apigw = ctx.client("apigateway")

    lambda_role_arn = _create_lambda_exec_role(ctx, iam)
    func_name = ctx.unique_name("sim2real-behav-authzfn-")
    zip_bytes = _zip_lambda_code(_AUTHORIZER_CODE)
    fn = _create_function_with_retry(ctx, lam, func_name, lambda_role_arn, zip_bytes)
    function_arn = fn["FunctionArn"]

    # Broken: trusted by apigateway but no invoke-permission policy attached at all.
    no_perm_role_arn = _create_authorizer_role(ctx, iam, "apigateway.amazonaws.com", allow_invoke_arn=None)
    # Control: identical trust, plus the missing invoke grant.
    with_perm_role_arn = _create_authorizer_role(
        ctx, iam, "apigateway.amazonaws.com", allow_invoke_arn=function_arn
    )

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-api-"), tags=_mgmt_tags())["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    no_perm_authorizer_id = _create_token_authorizer(
        ctx, apigw, api_id, "authz-no-perm", function_arn, no_perm_role_arn
    )
    with_perm_authorizer_id = _create_token_authorizer(
        ctx, apigw, api_id, "authz-with-perm", function_arn, with_perm_role_arn
    )

    no_perm_result = apigw.test_invoke_authorizer(
        restApiId=api_id, authorizerId=no_perm_authorizer_id, headers={"Authorization": "allow-me"}
    )
    assert no_perm_result["clientStatus"] == 500, f"expected 500 (invoke denied), got {no_perm_result}"
    assert not no_perm_result.get("policy"), "no policy should have been produced: Lambda never ran"

    with_perm_result = _poll_test_invoke(ctx, apigw, api_id, with_perm_authorizer_id, "allow-me")
    assert with_perm_result["clientStatus"] == 0, f"control authorizer should succeed, got {with_perm_result}"
    with_perm_policy = json.loads(with_perm_result["policy"])
    assert with_perm_policy["Statement"][0]["Effect"] == "Allow", (
        f"expected an Allow policy from the control authorizer, got {with_perm_policy}"
    )


def _mgmt_tags():
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


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
        Tags=[{"Key": k, "Value": v} for k, v in _mgmt_tags().items()],
    )["Role"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    # ctx.run_cleanups() pops LIFO, so register delete_role FIRST — it must run LAST, after the
    # policy is detached, or IAM refuses the delete (DeleteConflict) and the role leaks.
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
                Tags=_mgmt_tags(),
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
        Tags=[{"Key": k, "Value": v} for k, v in _mgmt_tags().items()],
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
