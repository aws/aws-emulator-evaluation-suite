"""cli-lambda-role-missing-trust-policy-negative."""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
import zipfile

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-lambda-role-missing-trust-policy-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateFunction rejects a role whose trust policy does not include lambda.amazonaws.com as a
    principal with InvalidParameterValueException, the function is never created, and the exact
    same workflow succeeds once the trust policy is corrected (positive control)."""
    require_tools("aws")

    # --- negative: role trusts ec2, not lambda ---
    bad_role_name = ctx.unique_name("sim2real-trust-bad-")
    bad_trust = _service_trust_policy("ec2.amazonaws.com")
    _run_aws(ctx, "iam", "create-role", "--role-name", bad_role_name,
              "--assume-role-policy-document", bad_trust)
    ctx.on_cleanup(lambda: _delete_role(ctx, bad_role_name))
    bad_role_arn = _run_aws(ctx, "iam", "get-role", "--role-name", bad_role_name)["Role"]["Arn"]

    handler_code = "def handler(event, context):\n    return {'ok': True}\n"
    zip_path = _write_zip(handler_code)
    bad_function_name = ctx.unique_name("sim2real-trust-bad-fn-")

    proc = _run_shell(ctx, [
        "aws", "--output", "json",
        "lambda", "create-function",
        "--function-name", bad_function_name,
        "--runtime", "python3.12",
        "--role", bad_role_arn,
        "--handler", "lambda_function.handler",
        "--zip-file", f"fileb://{zip_path}",
        "--timeout", "15",
    ], check=False, timeout_s=30.0)

    assert proc.returncode != 0, "create-function unexpectedly succeeded with a non-lambda-trusted role"
    code, message = _cli_error(proc.stderr, "CreateFunction")
    assert code == "InvalidParameterValueException", f"unexpected error code: {code!r} ({proc.stderr[-300:]})"
    assert message == "The role defined for the function cannot be assumed by Lambda.", (
        f"unexpected CreateFunction refusal message: {message!r}"
    )

    # effect absent: the function must not exist
    lam = ctx.client("lambda")
    err_code, err_message = _error_code(lambda: lam.get_function(FunctionName=bad_function_name))
    assert err_code == "ResourceNotFoundException", (
        f"expected the rejected function to be absent, got error {err_code!r}: {err_message!r}"
    )
    bad_function_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{bad_function_name}"
    assert err_message == f"Function not found: {bad_function_arn}", (
        f"unexpected GetFunction not-found message: {err_message!r}"
    )

    # --- positive control: same workflow, correct trust policy ---
    good_role_name = ctx.unique_name("sim2real-trust-good-")
    good_trust = _service_trust_policy("lambda.amazonaws.com")
    _run_aws(ctx, "iam", "create-role", "--role-name", good_role_name,
              "--assume-role-policy-document", good_trust)
    ctx.on_cleanup(lambda: _delete_role(ctx, good_role_name))
    _run_aws(ctx, "iam", "attach-role-policy", "--role-name", good_role_name,
              "--policy-arn", "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    good_role_arn = _run_aws(ctx, "iam", "get-role", "--role-name", good_role_name)["Role"]["Arn"]

    good_function_name = ctx.unique_name("sim2real-trust-good-fn-")
    result = _create_function_retrying(ctx, [
        "lambda", "create-function",
        "--function-name", good_function_name,
        "--runtime", "python3.12",
        "--role", good_role_arn,
        "--handler", "lambda_function.handler",
        "--zip-file", f"fileb://{zip_path}",
        "--timeout", "15",
    ])
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=good_function_name))
    assert result.get("FunctionArn"), f"positive control did not create a function: {result}"

    _wait_function_active(ctx, good_function_name)
    invoke_resp = lam.invoke(FunctionName=good_function_name, Payload=b"{}")
    assert invoke_resp.get("FunctionError") is None, f"unexpected function error: {invoke_resp}"
    body = json.loads(invoke_resp["Payload"].read())
    assert body == {"ok": True}, f"expected {{'ok': True}}, got {body!r}"


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


def _service_trust_policy(principal: str) -> str:
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


def _cli_error(stderr: str, operation: str) -> tuple[str | None, str | None]:
    """The (code, message) of the CLI's "An error occurred (<code>) when calling the <operation>
    operation: <message>" line."""
    match = re.search(
        r"An error occurred \(([A-Za-z0-9]+)\) when calling the " + operation + r" operation: (.*)",
        stderr,
    )
    return (match.group(1), match.group(2).strip()) if match else (None, None)


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
