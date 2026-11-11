"""cli-lambda-invoke-denied-without-rds-policy-negative."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import zipfile

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-lambda-invoke-denied-without-rds-policy-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role that reads its secret but has no rds:Describe* permission gets AccessDenied from RDS
    and no data; after the permission is attached to the same role, the invocation's scoped
    DescribeDBInstances returns the same count as a direct call."""
    require_tools("aws")

    secretsmanager = ctx.client("secretsmanager")
    secret_name = ctx.unique_name("sim2real-rdspolicy-secret-")
    secret = secretsmanager.create_secret(
        Name=secret_name,
        SecretString=json.dumps({"username": "probe", "password": "not-a-real-pw"}),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    role_name = ctx.unique_name("sim2real-rdspolicy-role-")
    trust = _lambda_trust_policy()
    _run_aws(ctx, "iam", "create-role", "--role-name", role_name, "--assume-role-policy-document", trust,
              "--tags", f"Key=sim2real-check,Value={CHECK}")
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    _run_aws(ctx, "iam", "attach-role-policy", "--role-name", role_name,
              "--policy-arn", "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    secret_only_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn}],
    })
    _run_aws(ctx, "iam", "put-role-policy", "--role-name", role_name,
              "--policy-name", "secret-only", "--policy-document", secret_only_policy)
    role_arn = _run_aws(ctx, "iam", "get-role", "--role-name", role_name)["Role"]["Arn"]

    handler_code = (
        "import json, os, boto3\n"
        "from botocore.exceptions import ClientError\n\n"
        "def handler(event, context):\n"
        "    secret_arn = os.environ['SECRET_ARN']\n"
        "    sm = boto3.client('secretsmanager')\n"
        "    try:\n"
        "        sm.get_secret_value(SecretId=secret_arn)\n"
        "        secret_ok = True\n"
        "    except ClientError:\n"
        "        secret_ok = False\n"
        "    rds = boto3.client('rds')\n"
        "    rds_success = False\n"
        "    rds_error_code = None\n"
        "    count = None\n"
        "    try:\n"
        "        resp = rds.describe_db_instances(\n"
        "            Filters=[{'Name': 'db-instance-id', 'Values': [os.environ['DB_ID']]}])\n"
        "        rds_success = True\n"
        "        count = len(resp.get('DBInstances', []))\n"
        "    except ClientError as e:\n"
        "        rds_error_code = e.response['Error']['Code']\n"
        "    return {'secret_ok': secret_ok, 'rds_success': rds_success,"
        " 'rds_error_code': rds_error_code, 'count': count}\n"
    )
    zip_path = _write_zip(handler_code)
    function_name = ctx.unique_name("sim2real-rdspolicy-fn-")
    # The handler's RDS read is scoped to a check-unique identifier, never the account inventory.
    db_id = ctx.unique_name("sim2real-rdspolicy-db-")

    _create_function_retrying(ctx, [
        "lambda", "create-function",
        "--function-name", function_name,
        "--runtime", "python3.12",
        "--role", role_arn,
        "--handler", "lambda_function.handler",
        "--zip-file", f"fileb://{zip_path}",
        "--timeout", "20",
        "--environment", json.dumps({"Variables": {"SECRET_ARN": secret_arn, "DB_ID": db_id}}),
        "--tags", f"sim2real-check={CHECK}",
    ])
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=function_name))
    _wait_function_active(ctx, function_name)

    lam = ctx.client("lambda")

    # --- negative: role has secret access but no RDS permission ---
    resp = lam.invoke(FunctionName=function_name, Payload=b"{}")
    assert resp.get("FunctionError") is None, f"handler itself crashed: {resp}"
    body = json.loads(resp["Payload"].read())
    assert body["secret_ok"] is True, "secret access should have succeeded (it was granted)"
    assert body["rds_success"] is False, "RDS call should have been denied"
    assert body["rds_error_code"] == "AccessDenied", f"unexpected RDS error code: {body['rds_error_code']!r}"
    assert body["count"] is None, "no RDS data should have been returned when the call was denied"

    # --- positive control: attach the missing RDS permission to the SAME role ---
    rds_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "rds:DescribeDBInstances", "Resource": "*"}],
    })
    _run_aws(ctx, "iam", "put-role-policy", "--role-name", role_name,
              "--policy-name", "rds-describe", "--policy-document", rds_policy)

    final_body = _invoke_until(ctx, function_name, lambda b: b["rds_success"] is True, timeout_s=60.0)
    assert final_body["rds_error_code"] is None, (
        f"expected no RDS error once rds:DescribeDBInstances was granted, got {final_body['rds_error_code']!r}"
    )
    direct_count = len(ctx.client("rds").describe_db_instances(
        Filters=[{"Name": "db-instance-id", "Values": [db_id]}]).get("DBInstances", []))
    assert final_body["count"] == 0 == direct_count, (
        f"a DescribeDBInstances filter on an unknown id returns an empty list; the lambda reported "
        f"{final_body['count']!r} and an independent read {direct_count}"
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


def _run_script(ctx, script: str, *, timeout_s=120.0, check=True, env_extra=None):
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
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _lambda_trust_policy() -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
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


def _invoke_until(ctx, function_name: str, predicate, timeout_s=60.0, interval_s=5.0):
    """IAM policy attachment is eventually consistent; poll invocations until the predicate on the
    parsed JSON body holds, or fail at the deadline with the last body seen."""
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last_body = None
    while time.monotonic() < deadline:
        resp = lam.invoke(FunctionName=function_name, Payload=b"{}")
        assert resp.get("FunctionError") is None, f"handler crashed: {resp}"
        last_body = json.loads(resp["Payload"].read())
        if predicate(last_body):
            return last_body
        time.sleep(interval_s)
    raise AssertionError(f"predicate never became true within {timeout_s}s; last body: {last_body}")


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
