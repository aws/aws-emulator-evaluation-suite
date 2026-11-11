"""cli-cognito-admin-create-user-lambda-invoke."""
from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import time
import zipfile

from behavioral_harness import tags

CHECK = "cli-cognito-admin-create-user-lambda-invoke"
GROUP = "cli-script"
SERVICES = ["apigateway", "cognito-idp", "lambda"]

_LAMBDA_CODE = (
    "import json\n"
    "import boto3\n"
    "def handler(event, context):\n"
    "    client = boto3.client('cognito-idp')\n"
    "    resp = client.admin_get_user(UserPoolId=event['user_pool_id'], Username=event['username'])\n"
    "    return {\n"
    "        'username': resp['Username'],\n"
    "        'status': resp['UserStatus'],\n"
    "        'enabled': resp['Enabled'],\n"
    "    }\n"
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda function that reads a Cognito user via boto3 sees the exact same
    Username/UserStatus/Enabled that the aws-CLI-driven admin-create-user just produced —
    cross-service read consistency between the CLI control plane and a Lambda's own SDK view."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    iam = ctx.client("iam")
    cognito = ctx.client("cognito-idp")
    lambda_client = ctx.client("lambda")

    pool_name = ctx.unique_name("sim2real-admin-pool-")
    pool_id = _run_aws(
        ctx,
        "cognito-idp",
        "create-user-pool",
        "--pool-name",
        pool_name,
        "--user-pool-tags",
        "sim2real:managed=true,sim2real:prefix=sim2real-admin",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    username = "sim2real-admin-user"
    _run_aws(
        ctx,
        "cognito-idp",
        "admin-create-user",
        "--user-pool-id",
        pool_id,
        "--username",
        username,
        "--user-attributes",
        "Name=email,Value=sim2real-admin@example.com",
        "--message-action",
        "SUPPRESS",
    )

    role_name = ctx.unique_name("sim2real-admin-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-admin"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_exec_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn))
    pool_arn = f"arn:aws:cognito-idp:{ctx.region}:{_account_id(ctx)}:userpool/{pool_id}"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="cognito-read",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "cognito-idp:AdminGetUser", "Resource": pool_arn}]}
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="cognito-read"))

    func_name = ctx.unique_name("sim2real-admin-fn-")
    _create_function_with_retry(
        ctx,
        FunctionName=func_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _zip_lambda(_LAMBDA_CODE)},
        Timeout=15,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-admin"},
    )
    ctx.on_cleanup(lambda: lambda_client.delete_function(FunctionName=func_name))
    _wait_for_function_active(ctx, func_name)

    payload_fd, payload_path = tempfile.mkstemp(suffix=".json")
    out_fd, out_path = tempfile.mkstemp(suffix=".json")
    os.close(payload_fd)
    os.close(out_fd)
    try:
        with open(payload_path, "w") as f:
            json.dump({"user_pool_id": pool_id, "username": username}, f)

        _run_shell(
            ctx,
            [
                "aws",
                "--output",
                "json",
                "lambda",
                "invoke",
                "--cli-binary-format",
                "raw-in-base64-out",
                "--function-name",
                func_name,
                "--payload",
                f"file://{payload_path}",
                out_path,
            ],
            timeout_s=30.0,
        )
        with open(out_path) as f:
            invoke_result = json.load(f)
    finally:
        os.unlink(payload_path)
        os.unlink(out_path)

    assert invoke_result["username"] == username, invoke_result
    assert invoke_result["status"] == "FORCE_CHANGE_PASSWORD", (
        f"a freshly admin-created user (no permanent password set) should be FORCE_CHANGE_PASSWORD, got {invoke_result}"
    )
    assert invoke_result["enabled"] is True, invoke_result


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
