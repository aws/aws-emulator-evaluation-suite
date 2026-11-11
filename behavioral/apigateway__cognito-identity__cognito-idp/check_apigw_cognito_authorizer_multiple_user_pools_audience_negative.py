"""apigw-cognito-authorizer-multiple-user-pools-audience-negative."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "apigw-cognito-authorizer-multiple-user-pools-audience-negative"
GROUP = "overly-permissive"
SERVICES = ["apigateway", "cognito-identity", "cognito-idp"]

_ECHO_CODE = """
def handler(event, context):
    return {"statusCode": 200, "body": "ok"}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An authorizer with Audience=[client_a] rejects a valid ID token from the same pool for client_b with 401
    and never reaches the integration, while client_a's token succeeds and reaches it."""
    cip = ctx.client("cognito-idp")
    lam = ctx.client("lambda")
    apigwv2 = ctx.client("apigatewayv2")
    sts = ctx.client("sts")
    iam = ctx.client("iam")

    pool_id, client_a, _client_b, token_a, token_b = _setup_user_pool_and_tokens(ctx, cip)
    issuer = ctx.service_url(f"https://cognito-idp.{ctx.region}.amazonaws.com") + f"/{pool_id}"

    lambda_role_arn = _create_lambda_exec_role(ctx, iam)
    func_name = ctx.unique_name("sim2real-behav-echofn-")
    fn = _create_function_with_retry(ctx, lam, func_name, lambda_role_arn, _zip_lambda_code(_ECHO_CODE))
    function_arn = fn["FunctionArn"]

    # Authorizer's audience only allows client_a.
    api_id, api_endpoint = _setup_http_api_route(
        ctx, apigwv2, lam, sts, function_arn, issuer, audience=[client_a]
    )
    apigwv2.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)

    url = f"{ctx.stage_url(api_endpoint, '$default')}/test"

    # Warm up on the control token first: confirms the API/integration is actually live before
    # we rely on a 401 meaning "rejected by audience check" rather than "not deployed yet".
    control_status, control_body = _poll_invoke(url, token_a)
    assert control_status == 200, f"control (client_a token) should succeed, got {control_status}: {control_body}"
    assert control_body == "ok", f"expected the integration echo body 'ok', got: {control_body!r}"

    # Now the mismatched-audience token: deterministic, no propagation window applies.
    bad_status, bad_body = _http_get(url, {"Authorization": f"Bearer {token_b}"})
    assert bad_status == 401, f"expected 401 for a token issued to an unlisted client, got {bad_status}: {bad_body}"
    assert bad_body != "ok", "the integration must never have been invoked for the rejected token"


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
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
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
                Tags={"sim2real": name},
            )
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            return resp
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(2)
    raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")


def _setup_user_pool_and_tokens(ctx, cip):
    pool_name = ctx.unique_name("sim2real-behav-pool-")
    pool_id = cip.create_user_pool(
        PoolName=pool_name,
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
        UserPoolTags={"sim2real": pool_name},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cip.delete_user_pool(UserPoolId=pool_id))

    client_a = cip.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-clienta-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    client_b = cip.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-clientb-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]

    username = "tester"
    password = "TestPass123"
    cip.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS"
    )
    cip.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    def _id_token(client_id):
        auth = cip.admin_initiate_auth(
            UserPoolId=pool_id,
            ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )
        return auth["AuthenticationResult"]["IdToken"]

    token_a = _id_token(client_a)
    token_b = _id_token(client_b)
    return pool_id, client_a, client_b, token_a, token_b


def _setup_http_api_route(ctx, apigwv2, lam, sts, function_arn, issuer, audience):
    account_id = sts.get_caller_identity()["Account"]
    api_name = ctx.unique_name("sim2real-behav-httpapi-")
    api = apigwv2.create_api(
        Name=api_name, ProtocolType="HTTP", Tags={"sim2real": api_name}
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: apigwv2.delete_api(ApiId=api_id))

    integration_id = apigwv2.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=function_arn,
        PayloadFormatVersion="2.0",
        IntegrationMethod="POST",
    )["IntegrationId"]

    statement_id = ctx.unique_name("sim2real-behav-perm-")
    source_arn = f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*/*"
    lam.add_permission(
        FunctionName=function_arn,
        StatementId=statement_id,
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=source_arn,
    )

    authorizer_id = apigwv2.create_authorizer(
        ApiId=api_id,
        AuthorizerType="JWT",
        IdentitySource=["$request.header.Authorization"],
        JwtConfiguration={"Audience": audience, "Issuer": issuer},
        Name=ctx.unique_name("sim2real-behav-jwtauthz-"),
    )["AuthorizerId"]

    apigwv2.create_route(
        ApiId=api_id,
        RouteKey="GET /test",
        AuthorizationType="JWT",
        AuthorizerId=authorizer_id,
        Target=f"integrations/{integration_id}",
    )

    return api_id, api["ApiEndpoint"]


def _http_get(url, headers, timeout_s=10.0):
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def _poll_invoke(url, token, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = (None, None)
    while time.monotonic() < deadline:
        status, body = _http_get(url, {"Authorization": f"Bearer {token}"})
        last = (status, body)
        if status == 200:
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
