"""cli-apigw-lambda-cognito-full-stack-smoke."""
from __future__ import annotations

import io
import json
import subprocess
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags

CHECK = "cli-apigw-lambda-cognito-full-stack-smoke"
GROUP = "cli-roundtrip"
SERVICES = ["apigateway", "cognito-idp", "lambda"]

_LAMBDA_CODE = (
    "import json\n"
    "def handler(event, context):\n"
    "    claims = event.get('requestContext', {}).get('authorizer', {}).get('claims', {})\n"
    "    return {\n"
    "        'statusCode': 200,\n"
    "        'body': json.dumps({'cognito_username': claims.get('cognito:username')}),\n"
    "    }\n"
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A valid ID token through a Cognito authorizer returns 200 and API Gateway forwards the decoded
    cognito:username claim to the Lambda proxy event, which echoes the authenticated username."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    iam = ctx.client("iam")
    lambda_client = ctx.client("lambda")
    apigw = ctx.client("apigateway")
    cognito = ctx.client("cognito-idp")

    role_name = ctx.unique_name("sim2real-fs-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_exec_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn))

    func_name = ctx.unique_name("sim2real-fs-fn-")
    fn = _create_function_with_retry(
        ctx,
        FunctionName=func_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _zip_lambda(_LAMBDA_CODE)},
        Timeout=15,
        Tags={"sim2real:managed": "true"},
    )
    fn_arn = fn["FunctionArn"]
    ctx.on_cleanup(lambda: lambda_client.delete_function(FunctionName=func_name))
    _wait_for_function_active(ctx, func_name)

    pool_id = _run_aws(
        ctx,
        "cognito-idp",
        "create-user-pool",
        "--pool-name",
        ctx.unique_name("sim2real-fs-pool-"),
        "--user-pool-tags",
        "sim2real:managed=true,sim2real:prefix=sim2real-fs",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client_id = _run_aws(
        ctx,
        "cognito-idp",
        "create-user-pool-client",
        "--user-pool-id",
        pool_id,
        "--client-name",
        ctx.unique_name("sim2real-fs-client-"),
        "--explicit-auth-flows",
        "ALLOW_ADMIN_USER_PASSWORD_AUTH",
        "--no-generate-secret",
    )["UserPoolClient"]["ClientId"]

    username, password = "sim2real-fs-user", "Sim2Real-Passw0rd!"
    _run_aws(
        ctx,
        "cognito-idp",
        "admin-create-user",
        "--user-pool-id",
        pool_id,
        "--username",
        username,
        "--user-attributes",
        "Name=email,Value=sim2real-fs@example.com",
        "--message-action",
        "SUPPRESS",
    )
    _run_aws(
        ctx,
        "cognito-idp",
        "admin-set-user-password",
        "--user-pool-id",
        pool_id,
        "--username",
        username,
        "--password",
        password,
        "--permanent",
    )
    id_token = _run_aws(
        ctx,
        "cognito-idp",
        "admin-initiate-auth",
        "--user-pool-id",
        pool_id,
        "--client-id",
        client_id,
        "--auth-flow",
        "ADMIN_USER_PASSWORD_AUTH",
        "--auth-parameters",
        f"USERNAME={username},PASSWORD={password}",
    )["AuthenticationResult"]["IdToken"]

    api_id = _run_aws(
        ctx,
        "apigateway",
        "create-rest-api",
        "--name",
        ctx.unique_name("sim2real-fs-api-"),
        "--tags",
        "sim2real:managed=true,sim2real:prefix=sim2real-fs",
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = _run_aws(ctx, "apigateway", "get-resources", "--rest-api-id", api_id)["items"][0]["id"]
    resource_id = _run_aws(
        ctx, "apigateway", "create-resource", "--rest-api-id", api_id, "--parent-id", root_id, "--path-part", "whoami"
    )["id"]

    account_id = _account_id(ctx)
    pool_arn = f"arn:aws:cognito-idp:{ctx.region}:{account_id}:userpool/{pool_id}"
    authorizer_id = _run_aws(
        ctx,
        "apigateway",
        "create-authorizer",
        "--rest-api-id",
        api_id,
        "--name",
        ctx.unique_name("sim2real-fs-authorizer-"),
        "--type",
        "COGNITO_USER_POOLS",
        "--provider-arns",
        pool_arn,
        "--identity-source",
        "method.request.header.Authorization",
        "--authorizer-result-ttl-in-seconds",
        "0",
    )["id"]
    _run_aws(
        ctx,
        "apigateway",
        "put-method",
        "--rest-api-id",
        api_id,
        "--resource-id",
        resource_id,
        "--http-method",
        "GET",
        "--authorization-type",
        "COGNITO_USER_POOLS",
        "--authorizer-id",
        authorizer_id,
    )
    integration_uri = f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fn_arn}/invocations"
    _run_aws(
        ctx,
        "apigateway",
        "put-integration",
        "--rest-api-id",
        api_id,
        "--resource-id",
        resource_id,
        "--http-method",
        "GET",
        "--type",
        "AWS_PROXY",
        "--integration-http-method",
        "POST",
        "--uri",
        integration_uri,
    )
    lambda_client.add_permission(
        FunctionName=func_name,
        StatementId=ctx.unique_name("sim2real-fs-invoke-"),
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*/GET/whoami",
    )
    _run_aws(ctx, "apigateway", "create-deployment", "--rest-api-id", api_id, "--stage-name", "prod")
    invoke_url = _rest_invoke_url(ctx, api_id, "prod", "whoami")

    # NOTE: apigateway.test_invoke_method deliberately bypasses authorizers (it always runs as
    # the caller's IAM identity and never populates requestContext.authorizer.claims), so the real
    # HTTP endpoint must be hit to observe the authorizer's decoded Cognito claims flow into Lambda.
    status, body_text = _http_get(invoke_url, headers={"Authorization": id_token})
    assert status == 200, f"full-stack smoke request should succeed, got status={status} body={body_text}"
    body = json.loads(body_text)
    assert body["cognito_username"] == username, (
        f"Lambda should observe the authenticated user's cognito:username claim, got {body}"
    )


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


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _zip_lambda(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _rest_invoke_url(ctx, api_id: str, stage: str, path: str) -> str:
    """The invoke URL of a DEPLOYED REST API stage, from ``ctx.rest_api_url``.

    Real AWS: ``https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/<path>``; under an
    emulator, the ``/_aws/execute-api/<id>/<stage>/<path>`` route (see ctx.rest_api_url).
    """
    return f"{ctx.rest_api_url(api_id, stage)}/{path}"


def _http_get(url: str, headers: dict | None = None, timeout_s: float = 45.0) -> tuple[int, str]:
    """GET url, retrying transient DNS/5xx errors while a freshly deployed stage propagates,
    and return (status_code, body_text)."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        req = urllib.request.Request(url, headers=headers or {}, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.getcode(), resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            if exc.code in (200, 401, 403):
                return exc.code, exc.read().decode("utf-8")
            last_exc = exc
        except urllib.error.URLError as exc:
            last_exc = exc
        time.sleep(2)
    raise AssertionError(f"GET {url} never resolved within {timeout_s}s: {last_exc}")


def _create_function_with_retry(ctx, *, timeout_s: float = 30.0, **kwargs):

    lambda_client = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return lambda_client.create_function(**kwargs)
        except lambda_client.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")


def _wait_for_function_active(ctx, function_name: str, timeout_s: float = 60.0) -> None:
    lambda_client = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = lambda_client.get_function_configuration(FunctionName=function_name)["State"]
        if state == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {function_name} never became Active")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
