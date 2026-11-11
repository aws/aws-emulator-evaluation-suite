"""apigw-cognito-user-pool-client-app-client-id-validation-positive."""
from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "apigw-cognito-user-pool-client-app-client-id-validation-positive"
GROUP = "arn-resolution"
SERVICES = ["apigateway", "cognito-identity", "cognito-idp"]

_ECHO_CODE = """
def handler(event, context):
    return {"statusCode": 200, "body": "ok"}
"""


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An HTTP API JWT authorizer with Audience=[<app client id>] accepts an ID token issued to that client and
    the request reaches the Lambda integration and returns its data."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    cip = ctx.client("cognito-idp")
    lam = ctx.client("lambda")
    apigwv2 = ctx.client("apigatewayv2")
    sts = ctx.client("sts")
    iam = ctx.client("iam")

    pool_id, client_a, _client_b, token_a, _token_b = _setup_user_pool_and_tokens(ctx, cip)
    issuer = ctx.service_url(f"https://cognito-idp.{ctx.region}.amazonaws.com") + f"/{pool_id}"

    lambda_role_arn = _create_lambda_exec_role(ctx, iam)
    func_name = ctx.unique_name("sim2real-behav-echofn-")
    fn = _create_function_with_retry(ctx, lam, func_name, lambda_role_arn, _zip_lambda_code(_ECHO_CODE))
    function_arn = fn["FunctionArn"]

    api_id, integration_id, authorizer_id, api_endpoint = _setup_http_api_route(
        ctx, apigwv2, lam, sts, function_arn, issuer, audience=[client_a]
    )

    # Deploy the stage via the AWS CLI (control-plane deploy step), not the SDK.
    _run_aws(
        ctx,
        "apigatewayv2",
        "create-stage",
        "--api-id",
        api_id,
        "--stage-name",
        "$default",
        "--auto-deploy",
        "--region",
        ctx.region,
    )

    url = f"{ctx.stage_url(api_endpoint, '$default')}/test"
    status, body = _poll_invoke(url, token_a)
    assert status == 200, f"expected 200 for a token issued to the configured client, got {status}: {body}"
    assert body == "ok", f"expected the real Lambda integration response, got {body!r}"


def _mgmt_tags():
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_script(ctx, script: str, *, timeout_s=120.0, check=True, env_extra=None):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write("#!/bin/bash\nset -euo pipefail\n")
        f.write(script)
        script_path = f.name
    try:
        os.chmod(script_path, 0o755)
        return _run_shell(ctx, ["bash", script_path], timeout_s=timeout_s, check=check, env_extra=env_extra)
    finally:
        os.unlink(script_path)


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    # Some installed `aws` CLI builds (v1, or older v2) don't recognize --no-cli-pager; output
    # is captured (not a tty) so no pager would ever invoke anyway. Disable paging via env
    # instead, which every CLI version honors.
    proc = _run_shell(
        ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check, env_extra={"AWS_PAGER": ""}
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


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


def _setup_user_pool_and_tokens(ctx, cip):
    pool_id = cip.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
        UserPoolTags=_mgmt_tags(),
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
    api = apigwv2.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=_mgmt_tags()
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

    return api_id, integration_id, authorizer_id, api["ApiEndpoint"]


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
