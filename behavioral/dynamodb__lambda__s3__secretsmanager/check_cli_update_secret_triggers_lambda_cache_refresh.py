"""cli-update-secret-triggers-lambda-cache-refresh."""
from __future__ import annotations

import io
import json
import subprocess
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "cli-update-secret-triggers-lambda-cache-refresh"
GROUP = "cli-workflow"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """aws secretsmanager update-secret changes the secret value; a Lambda function that
    fetches the secret fresh on every invocation observes the new value immediately,
    never the pre-update one."""
    require_tools("aws")

    secret_name = ctx.unique_name("sim2real-refresh-secret-")
    initial_value = "v1-" + ctx.unique_name("")
    updated_value = "v2-" + ctx.unique_name("")

    created = _run_aws(
        ctx,
        "secretsmanager",
        "create-secret",
        "--name",
        secret_name,
        "--secret-string",
        initial_value,
        "--tags",
        f"Key=sim2real,Value={CHECK}",
    )
    secret_arn = created["ARN"]
    ctx.on_cleanup(
        lambda: ctx.client("secretsmanager").delete_secret(
            SecretId=secret_arn, ForceDeleteWithoutRecovery=True
        )
    )

    role_arn = _create_lambda_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["secretsmanager:GetSecretValue"],
                "Resource": secret_arn,
            }
        ],
    )

    handler_code = (
        "import boto3, os\n"
        "def handler(event, context):\n"
        "    sm = boto3.client('secretsmanager')\n"
        "    resp = sm.get_secret_value(SecretId=os.environ['SECRET_ID'])\n"
        "    return {'secret_string': resp['SecretString']}\n"
    )
    fn_name = _create_function(ctx, role_arn, handler_code, env_vars={"SECRET_ID": secret_arn})

    _, body_before = _invoke(ctx, fn_name)
    assert body_before["secret_string"] == initial_value, body_before

    _run_aws(
        ctx, "secretsmanager", "update-secret", "--secret-id", secret_arn, "--secret-string", updated_value
    )

    # No caching layer in this handler, but real Secrets Manager version propagation
    # can lag by a moment right after the write; poll the observable outcome.
    deadline = time.monotonic() + 30.0
    body_after = None
    while time.monotonic() < deadline:
        _, body_after = _invoke(ctx, fn_name)
        if body_after["secret_string"] == updated_value:
            break
        time.sleep(2)
    assert body_after is not None and body_after["secret_string"] == updated_value, body_after
    assert body_after["secret_string"] != initial_value, (
        f"post-update read still returned the pre-update value: {body_after}"
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
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", *args],
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _make_zip(handler_code: str, filename="index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx, policy_statements, role_name=None):
    iam = ctx.client("iam")
    role_name = role_name or ctx.unique_name("sim2real-lam-role-")
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
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy))
    if policy_statements:
        policy_name = f"{role_name}-inline"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_function(ctx, role_arn, handler_code, handler="index.handler", env_vars=None, timeout=30):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    zip_bytes = _make_zip(handler_code)
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler=handler,
        Code={"ZipFile": zip_bytes},
        Timeout=timeout,
        Publish=False,
    )
    if env_vars:
        kwargs["Environment"] = {"Variables": env_vars}
    last_err = None
    for _ in range(8):  # bounded retry: the new IAM role has not yet propagated to Lambda
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(5)
    else:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_for_active(ctx, name)
    return name


def _wait_for_active(ctx, name, timeout_s=60.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {name} never became Active")


def _invoke(ctx, name, payload=None):
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=name, Payload=json.dumps(payload or {}).encode(), InvocationType="RequestResponse"
    )
    body = json.loads(resp["Payload"].read())
    return resp, body


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
