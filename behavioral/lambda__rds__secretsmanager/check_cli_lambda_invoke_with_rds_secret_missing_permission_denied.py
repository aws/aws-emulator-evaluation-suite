"""cli-lambda-invoke-with-rds-secret-missing-permission-denied."""
from __future__ import annotations

import io
import json
import os
import tempfile
import time
import zipfile

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-lambda-invoke-with-rds-secret-missing-permission-denied"
GROUP = "permission-boundary"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A function whose role lacks secretsmanager:GetSecretValue fails Unhandled with
    AccessDeniedException before reaching its RDS stage, while the same handler on a role with the grant
    returns the secret value."""
    require_tools("aws")

    secretsmanager = ctx.client("secretsmanager")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    name = ctx.unique_name("sim2real-permbound-").lower()
    secret_value = f"sim2real-rds-cred-{name}"

    secret = secretsmanager.create_secret(
        Name=f"{name}-secret", SecretString=secret_value,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: secretsmanager.delete_secret(
        SecretId=secret_arn, ForceDeleteWithoutRecovery=True
    ))

    # handler: fetches the secret first; only a successful fetch would let it "go on to query
    # RDS" (never reached here for the negative case, since get_secret_value raises first).
    handler_code = (
        "import boto3\n"
        "import os\n\n"
        "def handler(event, context):\n"
        "    sm = boto3.client('secretsmanager')\n"
        "    secret = sm.get_secret_value(SecretId=os.environ['SECRET_ARN'])\n"
        "    return {'stage': 'would_query_rds_here', 'secret_value': secret['SecretString']}\n"
    )
    zip_path = _write_zip(handler_code)
    ctx.on_cleanup(lambda: os.path.exists(zip_path) and os.unlink(zip_path))

    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    base_logs_stmt = {
        "Effect": "Allow", "Action": [
            "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents",
        ], "Resource": "*",
    }

    # --- negative role: no secretsmanager permission at all ----------------------------------
    deny_role_name = f"{name}-deny-role"
    deny_role = iam.create_role(
        RoleName=deny_role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    deny_role_arn = deny_role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=deny_role_name))
    iam.put_role_policy(
        RoleName=deny_role_name, PolicyName="logs-only",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [base_logs_stmt]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=deny_role_name, PolicyName="logs-only"))

    # --- positive control role: has secretsmanager:GetSecretValue on this exact secret ------
    allow_role_name = f"{name}-allow-role"
    allow_role = iam.create_role(
        RoleName=allow_role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    allow_role_arn = allow_role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=allow_role_name))
    iam.put_role_policy(
        RoleName=allow_role_name, PolicyName="allow-secret",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                base_logs_stmt,
                {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn},
            ],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=allow_role_name, PolicyName="allow-secret"))

    env_arg = json.dumps({"Variables": {"SECRET_ARN": secret_arn}})

    tags_arg = json.dumps({"sim2real-check": CHECK})

    deny_fn = f"{name}-deny-fn"
    _run_aws_with_retry(
        ctx, "lambda", "create-function",
        "--function-name", deny_fn, "--runtime", "python3.12", "--handler", "index.handler",
        "--role", deny_role_arn, "--zip-file", f"fileb://{zip_path}",
        "--environment", env_arg, "--timeout", "15", "--tags", tags_arg,
        retry_s=90,
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=deny_fn))

    allow_fn = f"{name}-allow-fn"
    _run_aws_with_retry(
        ctx, "lambda", "create-function",
        "--function-name", allow_fn, "--runtime", "python3.12", "--handler", "index.handler",
        "--role", allow_role_arn, "--zip-file", f"fileb://{zip_path}",
        "--environment", env_arg, "--timeout", "15", "--tags", tags_arg,
        retry_s=90,
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=allow_fn))

    for fn in (deny_fn, allow_fn):
        _poll_until(
            lambda fn=fn: lam.get_function_configuration(FunctionName=fn),
            lambda cfg: cfg["State"] == "Active" and cfg["LastUpdateStatus"] == "Successful",
            timeout_s=120, interval_s=5,
        )

    # --- negative: missing permission -> AccessDeniedException from Secrets Manager, and the
    # payload never reaches the "would query RDS" line -----------------------------------------
    deny_resp = lam.invoke(FunctionName=deny_fn, Payload=b"{}")
    assert deny_resp.get("FunctionError") == "Unhandled", (
        f"expected the unpermissioned invoke to raise, got FunctionError={deny_resp.get('FunctionError')!r}"
    )
    deny_payload = json.loads(deny_resp["Payload"].read())
    assert deny_payload["errorType"] == "ClientError", (
        f"expected a botocore ClientError, got errorType={deny_payload.get('errorType')!r}"
    )
    error_code = deny_payload["errorMessage"].split("(")[1].split(")")[0]
    assert error_code == "AccessDeniedException", (
        f"expected AccessDeniedException from Secrets Manager, got {error_code!r} "
        f"(errorMessage={deny_payload['errorMessage']!r})"
    )
    # the RDS-bound stage was never reached
    assert "stage" not in json.dumps(deny_payload), (
        f"handler must fail before reaching the RDS-bound stage, got payload={deny_payload!r}"
    )

    # --- positive control: identical code/env, only the role differs -> succeeds ------------
    allow_resp = lam.invoke(FunctionName=allow_fn, Payload=b"{}")
    assert "FunctionError" not in allow_resp, f"invoke failed: {allow_resp.get('FunctionError')}"
    allow_payload = json.loads(allow_resp["Payload"].read())
    assert allow_payload["stage"] == "would_query_rds_here", (
        f"expected the permissioned invoke to reach the RDS-bound stage, got {allow_payload!r}"
    )
    assert allow_payload["secret_value"] == secret_value, (
        f"expected the resolved secret value {secret_value!r}, got {allow_payload.get('secret_value')!r}"
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
