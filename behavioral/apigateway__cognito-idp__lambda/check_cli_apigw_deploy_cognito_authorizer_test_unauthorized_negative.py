"""cli-apigw-deploy-cognito-authorizer-test-unauthorized-negative."""
from __future__ import annotations

import io
import json
import subprocess
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-apigw-deploy-cognito-authorizer-test-unauthorized-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "cognito-idp", "lambda"]


_LAMBDA_CODE = (
    "import os\n"
    "import json\n"
    "import boto3\n"
    "def handler(event, context):\n"
    "    sqs = boto3.client('sqs')\n"
    "    sqs.send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody='invoked')\n"
    "    return {'statusCode': 200, 'body': json.dumps({'message': 'invoked'})}\n"
)


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A COGNITO_USER_POOLS method answers 401 to a request without an Authorization header and sends no SQS
    message from the integration, while the same request with a valid ID token succeeds and the message arrives."""
    require_tools("aws")

    iam = ctx.client("iam")
    sqs = ctx.client("sqs")
    lambda_client = ctx.client("lambda")
    apigw = ctx.client("apigateway")
    cognito = ctx.client("cognito-idp")

    # --- side-channel queue the Lambda writes to when (and only when) it is actually invoked ---
    resource_tags = {"sim2real:managed": "true", "sim2real:check": CHECK}
    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-pb-q-"), tags=resource_tags)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    role_name = ctx.unique_name("sim2real-pb-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": k, "Value": v} for k, v in resource_tags.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_exec_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sqs-send",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}]}
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sqs-send"))

    func_name = ctx.unique_name("sim2real-pb-fn-")
    fn = _create_function_with_retry(
        ctx,
        FunctionName=func_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _zip_lambda(_LAMBDA_CODE)},
        Timeout=15,
        Environment={"Variables": {"QUEUE_URL": queue_url}},
        Tags=resource_tags,
    )
    fn_arn = fn["FunctionArn"]
    ctx.on_cleanup(lambda: lambda_client.delete_function(FunctionName=func_name))
    _wait_for_function_active(ctx, func_name)

    # --- Cognito user pool + confirmed user + ID token (aws CLI) ---
    pool_name = ctx.unique_name("sim2real-pb-pool-")
    pool_id = _run_aws(
        ctx,
        "cognito-idp",
        "create-user-pool",
        "--pool-name",
        pool_name,
        "--user-pool-tags",
        json.dumps(resource_tags),
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client_id = _run_aws(
        ctx,
        "cognito-idp",
        "create-user-pool-client",
        "--user-pool-id",
        pool_id,
        "--client-name",
        ctx.unique_name("sim2real-pb-client-"),
        "--explicit-auth-flows",
        "ALLOW_ADMIN_USER_PASSWORD_AUTH",
        "--no-generate-secret",
    )["UserPoolClient"]["ClientId"]
    username, password = "sim2real-pb-user", "Sim2Real-Passw0rd!"
    _run_aws(
        ctx,
        "cognito-idp",
        "admin-create-user",
        "--user-pool-id",
        pool_id,
        "--username",
        username,
        "--user-attributes",
        "Name=email,Value=sim2real-pb@example.com",
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

    # --- API Gateway REST API + COGNITO_USER_POOLS authorizer + deployed stage (aws CLI) ---
    api_id = _run_aws(
        ctx,
        "apigateway",
        "create-rest-api",
        "--name",
        ctx.unique_name("sim2real-pb-api-"),
        "--tags",
        json.dumps(resource_tags),
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = _run_aws(ctx, "apigateway", "get-resources", "--rest-api-id", api_id)["items"][0]["id"]
    resource_id = _run_aws(
        ctx, "apigateway", "create-resource", "--rest-api-id", api_id, "--parent-id", root_id, "--path-part", "secure"
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
        ctx.unique_name("sim2real-pb-authorizer-"),
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
        StatementId=ctx.unique_name("sim2real-pb-invoke-"),
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*/GET/secure",
    )
    _run_aws(ctx, "apigateway", "create-deployment", "--rest-api-id", api_id, "--stage-name", "prod")
    invoke_url = f"{ctx.rest_api_url(api_id, 'prod')}/secure"

    # --- negative: no Authorization header -> 401, and Lambda is never reached ---
    # NOTE: apigateway.test_invoke_method deliberately bypasses authorizers (it always runs as
    # the caller's IAM identity), so the real HTTP endpoint must be hit to exercise the authorizer.
    unauth_status = _http_get_status(invoke_url)
    assert unauth_status == 401, f"expected 401 with no Authorization header, got {unauth_status}"
    unauth_messages = _drain_queue(ctx, queue_url, max_wait_s=8.0)
    assert unauth_messages == [], f"Lambda integration must not fire without authorization, got messages: {unauth_messages}"

    # --- negative: an Authorization header that is present but not a real pool token must also
    # be rejected -- without this leg, a stub that merely checks "is some Authorization header
    # present" (rather than validating it against the pool) would pass the check above unnoticed.
    bad_status = _http_get_status(invoke_url, headers={"Authorization": "not-a-real-cognito-token"})
    assert bad_status == 401, f"expected 401 for a syntactically-invalid bearer token, got {bad_status}"
    bad_messages = _drain_queue(ctx, queue_url, max_wait_s=8.0)
    assert bad_messages == [], f"Lambda integration must not fire for an invalid token, got messages: {bad_messages}"

    # --- positive control in the same file: a valid token reaches the Lambda integration ---
    auth_status = _http_get_status(invoke_url, headers={"Authorization": id_token})
    assert auth_status == 200, f"expected 200 with a valid Cognito ID token, got {auth_status}"
    auth_messages = _drain_queue(ctx, queue_url, max_wait_s=20.0)
    assert auth_messages == ["invoked"], f"expected exactly one side-channel message, got {auth_messages}"


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


def _http_get_status(url: str, headers: dict | None = None, timeout_s: float = 45.0) -> int:
    """GET url, retrying transient DNS/5xx errors while a freshly deployed stage propagates,
    and return the final HTTP status code (401/403/200 are returned immediately, not retried)."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        req = urllib.request.Request(url, headers=headers or {}, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.getcode()
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403, 200):
                return exc.code
            last_exc = exc
        except urllib.error.URLError as exc:
            last_exc = exc
        time.sleep(2)
    raise AssertionError(f"GET {url} never resolved within {timeout_s}s: {last_exc}")


def _drain_queue(ctx, queue_url: str, max_wait_s: float = 10.0) -> list[str]:
    """Poll the queue for up to max_wait_s and return the bodies of any messages received,
    deleting them as they are consumed."""
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    deadline = time.monotonic() + max_wait_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        msgs = resp.get("Messages", [])
        if not msgs:
            continue
        for msg in msgs:
            bodies.append(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if bodies:
            break
    return bodies


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
