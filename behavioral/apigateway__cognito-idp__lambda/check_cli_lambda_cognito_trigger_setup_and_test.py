"""cli-lambda-cognito-trigger-setup-and-test."""
from __future__ import annotations

import io
import json
import subprocess
import time
import zipfile

from behavioral_harness import tags

CHECK = "cli-lambda-cognito-trigger-setup-and-test"
GROUP = "cli-script"
SERVICES = ["apigateway", "cognito-idp", "lambda"]

_TRIGGER_CODE = (
    "def handler(event, context):\n"
    "    event.setdefault('response', {})\n"
    "    event['response']['autoConfirmUser'] = True\n"
    "    event['response']['autoVerifyEmail'] = True\n"
    "    return event\n"
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda attached as a Cognito PreSignUp trigger actually runs during SignUp:
    the trigger sets autoConfirmUser, and the CLI-observed SignUp response reflects it
    (UserConfirmed=true) rather than the pool's default unconfirmed state."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    iam = ctx.client("iam")
    lambda_client = ctx.client("lambda")
    cognito = ctx.client("cognito-idp")

    role_name = ctx.unique_name("sim2real-trig-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_exec_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn))

    func_name = ctx.unique_name("sim2real-trig-fn-")
    fn = _create_function_with_retry(
        ctx,
        FunctionName=func_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _zip_lambda(_TRIGGER_CODE)},
        Timeout=15,
    )
    fn_arn = fn["FunctionArn"]
    ctx.on_cleanup(lambda: lambda_client.delete_function(FunctionName=func_name))
    _wait_for_function_active(ctx, func_name)

    pool_name = ctx.unique_name("sim2real-trig-pool-")
    pool_out = _run_aws(ctx, "cognito-idp", "create-user-pool", "--pool-name", pool_name)
    pool_id = pool_out["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_out = _run_aws(
        ctx,
        "cognito-idp",
        "create-user-pool-client",
        "--user-pool-id",
        pool_id,
        "--client-name",
        ctx.unique_name("sim2real-trig-client-"),
        "--explicit-auth-flows",
        "ALLOW_USER_PASSWORD_AUTH",
        "--no-generate-secret",
    )
    client_id = client_out["UserPoolClient"]["ClientId"]

    lambda_client.add_permission(
        FunctionName=func_name,
        StatementId=ctx.unique_name("sim2real-cog-invoke-"),
        Action="lambda:InvokeFunction",
        Principal="cognito-idp.amazonaws.com",
        SourceArn=f"arn:aws:cognito-idp:{ctx.region}:{_account_id(ctx)}:userpool/{pool_id}",
    )

    _run_aws(
        ctx,
        "cognito-idp",
        "update-user-pool",
        "--user-pool-id",
        pool_id,
        "--lambda-config",
        f"PreSignUp={fn_arn}",
    )

    username = "sim2real-signup-user"
    signup_out = _run_aws(
        ctx,
        "cognito-idp",
        "sign-up",
        "--client-id",
        client_id,
        "--username",
        username,
        "--password",
        "Sim2Real-Passw0rd!",
        "--user-attributes",
        "Name=email,Value=sim2real-signup@example.com",
    )

    assert signup_out["UserConfirmed"] is True, (
        "PreSignUp trigger should have auto-confirmed the user via SignUp's UserConfirmed flag; "
        f"got: {signup_out}"
    )

    user = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert user["UserStatus"] == "CONFIRMED", (
        "an independent AdminGetUser read should show CONFIRMED after the PreSignUp trigger "
        f"auto-confirmed the user, got {user['UserStatus']}"
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
