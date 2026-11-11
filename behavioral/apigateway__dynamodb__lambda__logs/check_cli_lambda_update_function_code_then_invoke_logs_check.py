"""cli-lambda-update-function-code-then-invoke-logs-check."""
from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import time
import zipfile

from behavioral_harness import tags

CHECK = "cli-lambda-update-function-code-then-invoke-logs-check"
GROUP = "cli-roundtrip"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """CLI `update-function-code` swaps the deployed code; a subsequent CLI invoke executes
    the NEW code path, proven by a new log marker appearing in CloudWatch Logs while the
    old marker never appears for the post-update invocation."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    code_a = (
        "def handler(event, context):\n"
        "    print('MARKER_VERSION_A')\n"
        "    return {'version': 'A'}\n"
    )
    code_b = (
        "def handler(event, context):\n"
        "    print('MARKER_VERSION_B')\n"
        "    return {'version': 'B'}\n"
    )

    fn = _create_lambda_function(ctx, code_a)
    log_group = f"/aws/lambda/{fn['name']}"

    # Baseline invoke on version A via CLI.
    meta_a, payload_a = _cli_invoke(ctx, fn["name"])
    assert meta_a.get("StatusCode") == 200
    assert payload_a == {"version": "A"}
    assert _wait_for_log_marker(ctx, log_group, "MARKER_VERSION_A", timeout_s=60.0)
    assert not _log_has_marker(ctx, log_group, "MARKER_VERSION_B")

    # Update code via CLI.
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as zf:
        zf.write(_make_zip(code_b))
        zip_path = zf.name
    try:
        _run_aws(
            ctx, "lambda", "update-function-code", "--function-name", fn["name"],
            "--zip-file", f"fileb://{zip_path}",
        )
    finally:
        os.unlink(zip_path)

    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while True:
        cfg = _run_aws(ctx, "lambda", "get-function-configuration", "--function-name", fn["name"])
        if cfg.get("LastUpdateStatus") == "Successful" and cfg.get("State") == "Active":
            break
        if time.monotonic() >= deadline:
            raise AssertionError("update-function-code never reached LastUpdateStatus=Successful")
        time.sleep(2)

    # Invoke again via CLI: must now run version B's code.
    meta_b, payload_b = _cli_invoke(ctx, fn["name"])
    assert meta_b.get("StatusCode") == 200
    assert payload_b == {"version": "B"}
    assert _wait_for_log_marker(ctx, log_group, "MARKER_VERSION_B", timeout_s=60.0)


# ===== helpers =====


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command, shell=isinstance(command, str), env=env, capture_output=True,
        text=True, timeout=timeout_s, cwd=cwd,
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


def _cli_invoke(ctx, function_name: str):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name
    try:
        meta = _run_aws(
            ctx, "lambda", "invoke", "--function-name", function_name,
            "--cli-binary-format", "raw-in-base64-out", "--payload", "{}", out_path,
        )
        with open(out_path) as fh:
            payload = json.load(fh)
        return meta, payload
    finally:
        os.unlink(out_path)


def _make_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lmbrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_lambda_function(ctx, code: str, env_vars=None, handler="lambda_function.handler", timeout=10) -> dict:
    lam = ctx.client("lambda")
    role_arn = _create_lambda_role(ctx)
    name = ctx.unique_name("sim2real-fn-")
    zip_bytes = _make_zip(code)
    resp = None
    last_err = None
    for _ in range(15):
        try:
            resp = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn, Handler=handler,
                Code={"ZipFile": zip_bytes}, Timeout=timeout, Environment={"Variables": env_vars or {}},
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(2)
    if resp is None:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while lam.get_function(FunctionName=name)["Configuration"]["State"] != "Active":
        if time.monotonic() >= deadline:
            raise AssertionError("lambda function never became Active")
        time.sleep(2)
    return {"name": name, "arn": resp["FunctionArn"]}


def _log_has_marker(ctx, log_group: str, marker: str) -> bool:
    logs = ctx.client("logs")
    try:
        resp = logs.filter_log_events(logGroupName=log_group, filterPattern=f'"{marker}"')
    except logs.exceptions.ResourceNotFoundException:
        return False
    return bool(resp.get("events"))


def _wait_for_log_marker(ctx, log_group: str, marker: str, timeout_s=60.0, interval_s=3.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _log_has_marker(ctx, log_group, marker):
            return True
        time.sleep(interval_s)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
