"""cli-lambda-update-env-with-secret-arn."""
from __future__ import annotations

import io
import json
import os
import tempfile
import time
import zipfile

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-lambda-update-env-with-secret-arn"
GROUP = "cli-roundtrip"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A function with a placeholder SECRET_ARN fails Unhandled; after `aws lambda
    update-function-configuration` sets the real ARN and LastUpdateStatus is Successful, the next
    invoke returns the secret value."""
    require_tools("aws")

    secretsmanager = ctx.client("secretsmanager")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    name = ctx.unique_name("sim2real-envup-").lower()
    secret_value = f"sim2real-secret-value-{name}"

    secret = secretsmanager.create_secret(
        Name=f"{name}-secret", SecretString=secret_value,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: secretsmanager.delete_secret(
        SecretId=secret_arn, ForceDeleteWithoutRecovery=True
    ))

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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn},
            {"Effect": "Allow", "Action": [
                "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents",
            ], "Resource": "*"},
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline-envup", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline-envup"))

    handler_code = (
        "import boto3\n"
        "import os\n\n"
        "def handler(event, context):\n"
        "    sm = boto3.client('secretsmanager')\n"
        "    val = sm.get_secret_value(SecretId=os.environ['SECRET_ARN'])['SecretString']\n"
        "    return {'secret_value': val}\n"
    )
    zip_path = _write_zip(handler_code)
    ctx.on_cleanup(lambda: os.path.exists(zip_path) and os.unlink(zip_path))

    fn_name = f"{name}-fn"
    _run_aws_with_retry(
        ctx,
        "lambda", "create-function",
        "--function-name", fn_name,
        "--runtime", "python3.12",
        "--handler", "index.handler",
        "--role", role_arn,
        "--zip-file", f"fileb://{zip_path}",
        "--environment", json.dumps({"Variables": {"SECRET_ARN": "arn:aws:secretsmanager:placeholder"}}),
        "--timeout", "30",
        "--tags", f"sim2real-check={CHECK}",
        retry_s=90,
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn_name),
        lambda cfg: cfg["State"] == "Active" and cfg["LastUpdateStatus"] == "Successful",
        timeout_s=120, interval_s=5,
    )

    # placeholder env var cannot resolve a real secret
    resp = lam.invoke(FunctionName=fn_name, Payload=b"{}")
    assert resp.get("FunctionError") == "Unhandled", (
        f"expected the placeholder SECRET_ARN to fail the invoke with FunctionError=Unhandled, "
        f"got FunctionError={resp.get('FunctionError')!r}"
    )

    # --- CLI updates the environment to point at the real secret ARN -----------------------
    _run_aws(
        ctx, "lambda", "update-function-configuration",
        "--function-name", fn_name,
        "--environment", json.dumps({"Variables": {"SECRET_ARN": secret_arn}}),
    )
    cfg = _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn_name),
        lambda cfg: cfg["LastUpdateStatus"] in ("Successful", "Failed"),
        timeout_s=120, interval_s=3,
    )
    assert cfg["LastUpdateStatus"] == "Successful", (
        f"expected the CLI environment update to reach LastUpdateStatus=Successful, "
        f"got {cfg['LastUpdateStatus']!r} (reason: {cfg.get('LastUpdateStatusReason')!r})"
    )
    assert cfg["Environment"]["Variables"]["SECRET_ARN"] == secret_arn, (
        f"expected the read-back configuration to reflect the CLI update, "
        f"got SECRET_ARN={cfg['Environment']['Variables'].get('SECRET_ARN')!r} "
        f"expected {secret_arn!r}"
    )

    resp = lam.invoke(FunctionName=fn_name, Payload=b"{}")
    assert "FunctionError" not in resp, f"invoke failed: {resp.get('FunctionError')}"
    payload = json.loads(resp["Payload"].read())
    assert payload["secret_value"] == secret_value, (
        f"expected the invoke to fetch and return the real secret value, "
        f"got {payload.get('secret_value')!r} expected {secret_value!r}"
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
