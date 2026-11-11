"""cli-lambda-create-function-missing-role-negative."""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
import zipfile
from io import BytesIO

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-lambda-create-function-missing-role-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """aws lambda create-function fails with InvalidParameterValueException, and no function is
    created, when given a role ARN for a role that does not exist. The same create-function call
    with a real, existing role (positive control) succeeds."""
    require_tools("aws")

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    function_name = ctx.unique_name("sim2real-norolefn-")
    zip_path = _write_zip("def handler(event, context):\n    return {'ok': True}\n")

    try:
        # Negative: a syntactically valid but nonexistent role ARN in this account.
        bogus_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-does-not-exist-role-xyz"
        bad_args = [
            "lambda", "create-function",
            "--function-name", function_name,
            "--runtime", "python3.12",
            "--role", bogus_role_arn,
            "--handler", "index.handler",
            "--zip-file", f"fileb://{zip_path}",
            "--timeout", "10",
        ]
        proc = _run_shell(ctx, ["aws", "--output", "json", *bad_args], check=False)
        assert proc.returncode != 0, "create-function unexpectedly succeeded with a nonexistent role ARN"
        code = _cli_error_code(proc.stderr)
        assert code == "InvalidParameterValueException", f"expected InvalidParameterValueException, got {code}"

        # Effect-absent: the function was never created.
        describe = _run_shell(
            ctx, ["aws", "--output", "json", "lambda", "get-function",
                  "--function-name", function_name],
            check=False,
        )
        assert describe.returncode != 0, (
            f"get-function on {function_name!r} unexpectedly succeeded after the rejected "
            f"create-function call; the function must not exist"
        )
        describe_code = _cli_error_code(describe.stderr)
        assert describe_code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException from get-function on {function_name!r}, "
            f"got {describe_code!r}"
        )

        # Positive control: same create-function call, but with a real, existing role, succeeds.
        role_name = ctx.unique_name("sim2real-norolefn-role-")
        managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }
        trust_path = _write_temp_json(trust_policy)
        try:
            role = _run_aws(
                ctx, "iam", "create-role",
                "--role-name", role_name,
                "--assume-role-policy-document", f"file://{trust_path}",
                "--tags", f"Key=sim2real,Value={CHECK}",
            )
            role_arn = role["Role"]["Arn"]
            ctx.on_cleanup(lambda: _run_shell(
                ctx, ["aws", "iam", "delete-role", "--role-name", role_name], check=False,
            ))
            _run_aws(ctx, "iam", "attach-role-policy", "--role-name", role_name, "--policy-arn", managed_policy_arn)
            ctx.on_cleanup(lambda: _run_shell(
                ctx, ["aws", "iam", "detach-role-policy", "--role-name", role_name,
                      "--policy-arn", managed_policy_arn], check=False,
            ))
        finally:
            os.unlink(trust_path)

        good_args = [
            "lambda", "create-function",
            "--function-name", function_name,
            "--runtime", "python3.12",
            "--role", role_arn,
            "--handler", "index.handler",
            "--zip-file", f"fileb://{zip_path}",
            "--timeout", "10",
            "--tags", f"sim2real={CHECK}",
        ]
        _create_function_with_role_propagation_retry(ctx, good_args)
        ctx.on_cleanup(lambda: _run_shell(
            ctx, ["aws", "lambda", "delete-function", "--function-name", function_name], check=False,
        ))

        created = _poll_until(
            lambda: _run_shell(
                ctx, ["aws", "--output", "json", "lambda", "get-function",
                      "--function-name", function_name],
                check=False,
            ).returncode,
            lambda rc: rc == 0,
            timeout_s=30, interval_s=2,
        )
        assert created == 0, "positive control: function should now exist with a valid role"
    finally:
        os.unlink(zip_path)


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


def _write_temp_json(obj) -> str:
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f)
    return path


def _write_zip(handler_source: str) -> str:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_source)
    fd, path = tempfile.mkstemp(suffix=".zip")
    with os.fdopen(fd, "wb") as f:
        f.write(buf.getvalue())
    return path


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_function_with_role_propagation_retry(ctx, create_args, *, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_err = ""
    while time.monotonic() < deadline:
        proc = _run_shell(ctx, ["aws", "--output", "json", *create_args], check=False)
        if proc.returncode == 0:
            return json.loads(proc.stdout) if proc.stdout.strip() else {}
        last_err = proc.stderr
        if "InvalidParameterValueException" in proc.stderr and "assumed" in proc.stderr:
            time.sleep(interval_s)
            continue
        raise AssertionError(f"create-function failed: {last_err[-500:]}")
    raise AssertionError(f"create-function never succeeded after role propagation wait: {last_err[-500:]}")


def _cli_error_code(stderr: str):
    m = re.search(r"An error occurred \(([A-Za-z0-9]+)\)", stderr)
    return m.group(1) if m else None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
