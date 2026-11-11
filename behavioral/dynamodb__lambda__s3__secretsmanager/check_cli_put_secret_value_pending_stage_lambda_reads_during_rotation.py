"""cli-put-secret-value-pending-stage-lambda-reads-during-rotation."""
from __future__ import annotations

import io
import json
import subprocess
import time
import uuid
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "cli-put-secret-value-pending-stage-lambda-reads-during-rotation"
GROUP = "data-format"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """aws secretsmanager put-secret-value with --version-stages AWSPENDING adds a
    version staged distinctly from AWSCURRENT; a Lambda function that fetches both
    stages explicitly observes two different values, not a single collapsed one."""
    require_tools("aws")

    sm = ctx.client("secretsmanager")
    secret_name = ctx.unique_name("sim2real-pending-secret-")
    current_value = "current-" + ctx.unique_name("")
    pending_value = "pending-" + ctx.unique_name("")
    pending_token = str(uuid.uuid4())

    created = _run_aws(
        ctx, "secretsmanager", "create-secret", "--name", secret_name, "--secret-string", current_value
    )
    secret_arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    _run_aws(
        ctx,
        "secretsmanager",
        "put-secret-value",
        "--secret-id",
        secret_arn,
        "--secret-string",
        pending_value,
        "--version-stages",
        "AWSPENDING",
        "--client-request-token",
        pending_token,
    )

    # AWSCURRENT must remain the original value; only AWSPENDING carries the new one.
    meta = sm.describe_secret(SecretId=secret_arn)
    stages = meta["VersionIdsToStages"]
    current_versions = [v for v, s in stages.items() if "AWSCURRENT" in s]
    assert len(current_versions) == 1
    assert "AWSPENDING" in stages.get(pending_token, []), stages

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
        "    sid = os.environ['SECRET_ID']\n"
        "    cur = sm.get_secret_value(SecretId=sid, VersionStage='AWSCURRENT')['SecretString']\n"
        "    pend = sm.get_secret_value(SecretId=sid, VersionStage='AWSPENDING')['SecretString']\n"
        "    return {'current': cur, 'pending': pend}\n"
    )
    fn_name = _create_function(ctx, role_arn, handler_code, env_vars={"SECRET_ID": secret_arn})

    _, body = _invoke(ctx, fn_name)
    assert body["current"] == current_value, body
    assert body["pending"] == pending_value, body
    assert body["current"] != body["pending"]


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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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
    for _ in range(8):
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
