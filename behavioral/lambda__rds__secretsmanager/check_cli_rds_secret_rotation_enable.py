"""cli-rds-secret-rotation-enable."""
from __future__ import annotations

import io
import json
import os
import tempfile
import time
import zipfile

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-rds-secret-rotation-enable"
GROUP = "cli-roundtrip"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """`aws secretsmanager rotate-secret` with RotateImmediately false stores RotationEnabled, the
    rotation Lambda ARN and a 30-day AutomaticallyAfterDays on the secret."""
    require_tools("aws")

    secretsmanager = ctx.client("secretsmanager")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    name = ctx.unique_name("sim2real-rot-").lower()

    secret = _run_aws(
        ctx, "secretsmanager", "create-secret",
        "--name", f"{name}-secret",
        "--secret-string", json.dumps({"username": "dbadmin", "password": "P4ssw0rd12345!"}),
        "--tags", "Key=sim2real:managed,Value=true",
    )
    secret_arn = secret["ARN"]

    def _cleanup_secret():
        try:
            secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
        except secretsmanager.exceptions.ResourceNotFoundException:
            pass

    ctx.on_cleanup(_cleanup_secret)

    role_name = f"{name}-role"
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": [
                "secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret",
                "secretsmanager:PutSecretValue", "secretsmanager:UpdateSecretVersionStage",
            ], "Resource": secret_arn},
            {"Effect": "Allow", "Action": [
                "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents",
            ], "Resource": "*"},
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline-rotation", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline-rotation"))

    # a minimal rotation-function stub -- never invoked in this check (RotateImmediately=false)
    handler_code = (
        "def handler(event, context):\n"
        "    return {'step': event.get('Step', 'noop')}\n"
    )
    zip_path = _write_zip(handler_code)
    ctx.on_cleanup(lambda: os.path.exists(zip_path) and os.unlink(zip_path))

    fn_name = f"{name}-rotator"
    _run_aws_with_retry(
        ctx,
        "lambda", "create-function",
        "--function-name", fn_name,
        "--runtime", "python3.12",
        "--handler", "index.handler",
        "--role", role_arn,
        "--zip-file", f"fileb://{zip_path}",
        "--timeout", "30",
        "--tags", "sim2real:managed=true",
        retry_s=90,
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    fn_arn = _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn_name),
        lambda cfg: cfg["State"] == "Active",
        timeout_s=120, interval_s=5,
    )["FunctionArn"]

    _run_aws(
        ctx, "lambda", "add-permission",
        "--function-name", fn_name,
        "--statement-id", "AllowSecretsManagerInvoke",
        "--action", "lambda:InvokeFunction",
        "--principal", "secretsmanager.amazonaws.com",
    )

    _run_aws(
        ctx, "secretsmanager", "rotate-secret",
        "--secret-id", secret_arn,
        "--rotation-lambda-arn", fn_arn,
        "--rotation-rules", "AutomaticallyAfterDays=30",
        "--no-rotate-immediately",
    )

    described = secretsmanager.describe_secret(SecretId=secret_arn)
    assert described["RotationEnabled"] is True, (
        f"expected RotationEnabled=True after rotate-secret, got {described.get('RotationEnabled')!r}"
    )
    assert described["RotationLambdaARN"] == fn_arn, (
        f"expected RotationLambdaARN={fn_arn!r}, got {described.get('RotationLambdaARN')!r}"
    )
    assert described["RotationRules"]["AutomaticallyAfterDays"] == 30, (
        f"expected RotationRules.AutomaticallyAfterDays=30, got {described.get('RotationRules')!r}"
    )

    # the delete this check already performs at cleanup is a free negative assertion: prove an
    # actively rotation-enabled secret is force-deletable and independently reads as gone.
    # DescribeSecret does not reflect ForceDeleteWithoutRecovery synchronously -- it keeps answering
    # with the pre-delete metadata for a few seconds -- so this polls for either the not-found error
    # or the DeletedDate marker DescribeSecret's own contract uses to say "gone".
    secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)

    def _deleted_state():
        try:
            return secretsmanager.describe_secret(SecretId=secret_arn)
        except secretsmanager.exceptions.ResourceNotFoundException:
            return None

    _poll_until(
        _deleted_state,
        lambda resp: resp is None or resp.get("DeletedDate") is not None,
        timeout_s=30, interval_s=3,
    )


import subprocess


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


def _run_aws(ctx, *args: str, timeout_s=60.0, check=True):
    proc = _run_shell(
        ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _run_aws_with_retry(ctx, *args: str, retry_s=90.0, interval_s=5.0, timeout_s=60.0):
    deadline = time.monotonic() + retry_s
    last_err = None
    while time.monotonic() < deadline:
        proc = _run_shell(
            ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=False
        )
        if proc.returncode == 0:
            if not proc.stdout.strip():
                return {}
            try:
                return json.loads(proc.stdout)
            except (json.JSONDecodeError, ValueError):
                return proc.stdout.strip()
        last_err = proc.stderr
        time.sleep(interval_s)
    raise AssertionError(f"command never succeeded within {retry_s}s: {args}\nlast error: {last_err}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s (last value: {last!r})")


def _write_zip(handler_code: str) -> str:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
        f.write(buf.getvalue())
        return f.name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
