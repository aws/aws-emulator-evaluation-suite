"""cli-create-lambda-role-trust-policy-lambda-service."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import zipfile

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-create-lambda-role-trust-policy-lambda-service"
GROUP = "iam-trust"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A function using a role that trusts lambda.amazonaws.com runs as that role: its handler echoes the
    payload and GetCallerIdentity returns an assumed-role ARN for the role name."""
    require_tools("aws")

    role_name = ctx.unique_name("sim2real-trust-ok-")
    trust = _lambda_trust_policy("lambda.amazonaws.com")
    _run_aws(ctx, "iam", "create-role", "--role-name", role_name,
              "--assume-role-policy-document", trust,
              "--tags", "Key=sim2real,Value=true")
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    _run_aws(ctx, "iam", "attach-role-policy", "--role-name", role_name,
              "--policy-arn", "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")

    role_arn = _run_aws(ctx, "iam", "get-role", "--role-name", role_name)["Role"]["Arn"]

    handler_code = (
        "import boto3\n\n"
        "def handler(event, context):\n"
        "    identity = boto3.client('sts').get_caller_identity()\n"
        "    return {'echo': event, 'caller_arn': identity['Arn']}\n"
    )
    zip_path = _write_zip(handler_code)
    function_name = ctx.unique_name("sim2real-trust-ok-fn-")

    _create_function_retrying(ctx, [
        "lambda", "create-function",
        "--function-name", function_name,
        "--runtime", "python3.12",
        "--role", role_arn,
        "--handler", "lambda_function.handler",
        "--zip-file", f"fileb://{zip_path}",
        "--timeout", "15",
        "--tags", "sim2real=true",
    ])
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=function_name))

    _wait_function_active(ctx, function_name)

    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=function_name, Payload=json.dumps({"ping": "pong"}).encode())
    assert resp.get("FunctionError") is None, f"unexpected function error: {resp}"
    body = json.loads(resp["Payload"].read())
    assert body["echo"] == {"ping": "pong"}, f"expected echoed payload {{'ping': 'pong'}}, got {body['echo']!r}"
    assert f"assumed-role/{role_name}/" in body["caller_arn"], (
        f"expected assumed-role ARN for {role_name}, got {body['caller_arn']}"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    """Run a shell command with leased AWS creds + region in the env."""
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
    """Run a multi-line bash script (set -euo pipefail) with leased AWS creds configured."""
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
    """Run an AWS CLI command; return parsed JSON (dict/list) or raw stdout string."""
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _lambda_trust_policy(principal: str) -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": principal},
            "Action": "sts:AssumeRole",
        }],
    })


def _write_zip(handler_code: str) -> str:
    tmp_dir = tempfile.mkdtemp()
    src_path = os.path.join(tmp_dir, "lambda_function.py")
    with open(src_path, "w") as f:
        f.write(handler_code)
    zip_path = os.path.join(tmp_dir, "function.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(src_path, arcname="lambda_function.py")
    return zip_path


def _create_function_retrying(ctx, args, timeout_s=90.0):
    """create-function can transiently fail right after CreateRole with 'cannot be assumed by
    Lambda' due to IAM eventual consistency; retry until the deadline."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        proc = _run_shell(ctx, ["aws", "--output", "json", *args], check=False, timeout_s=30.0)
        if proc.returncode == 0:
            return json.loads(proc.stdout) if proc.stdout.strip() else {}
        if "cannot be assumed by Lambda" in proc.stderr:
            last_err = proc.stderr
            time.sleep(3)
            continue
        raise AssertionError(f"create-function failed: {proc.stderr[-500:]}")
    raise AssertionError(f"create-function kept failing on role assumption after {timeout_s}s: {last_err}")


def _wait_function_active(ctx, function_name: str, timeout_s=90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=function_name)
        if cfg.get("State") == "Active" and cfg.get("LastUpdateStatus") == "Successful":
            return
        if cfg.get("State") == "Failed":
            raise AssertionError(f"function {function_name} entered Failed state: {cfg.get('StateReason')}")
        time.sleep(2)
    raise AssertionError(f"function {function_name} did not become Active within {timeout_s}s")


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
        iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    for pol_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pol_name)
    iam.delete_role(RoleName=role_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
