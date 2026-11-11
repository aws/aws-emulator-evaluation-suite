"""cli-lambda-missing-log-permission-negative."""
from __future__ import annotations

import json
import shutil
import subprocess
import time
import io
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cli-lambda-missing-log-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "lambda", "logs"]


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """`aws lambda invoke` returns 200 for a function whose role lacks Logs permissions, yet no log
    stream exists for it while a permissioned sibling gets one; attaching the permission to the
    same role and re-invoking restores log delivery, so the permission caused the absence."""
    if not _aws_cli_available(ctx):
        raise AssertionError("aws CLI not available on PATH in the child-process environment")

    logs = ctx.client("logs")
    iam = ctx.client("iam")

    # --- function A: role has NO logging permissions at all ---
    role_name_no_logs = ctx.unique_name("sim2real-behav-role-")
    role_no_logs = _create_lambda_role(ctx, role_name_no_logs, with_logs_permission=False)
    fn_no_logs = ctx.unique_name("sim2real-behav-nologsfn-")
    handler_code = "def handler(event, context):\n    return 'ok-no-logs'\n"
    _create_function(ctx, fn_no_logs, role_no_logs, handler_code)

    # --- function B: role HAS AWSLambdaBasicExecutionRole (positive control) ---
    role_name_with_logs = ctx.unique_name("sim2real-behav-role-")
    role_with_logs = _create_lambda_role(ctx, role_name_with_logs, with_logs_permission=True)
    fn_with_logs = ctx.unique_name("sim2real-behav-withlogsfn-")
    _create_function(ctx, fn_with_logs, role_with_logs, handler_code)

    invoke_a = _run_aws(
        ctx, "lambda", "invoke", "--function-name", fn_no_logs,
        "--payload", "{}", "/dev/null",
    )
    invoke_b = _run_aws(
        ctx, "lambda", "invoke", "--function-name", fn_with_logs,
        "--payload", "{}", "/dev/null",
    )
    assert invoke_a.get("StatusCode") == 200, f"no-logs-role invoke unexpectedly failed: {invoke_a}"
    assert "FunctionError" not in invoke_a, f"no-logs-role invoke reported a function error: {invoke_a}"
    assert invoke_b.get("StatusCode") == 200, f"with-logs-role invoke unexpectedly failed: {invoke_b}"

    group_a = f"/aws/lambda/{fn_no_logs}"
    group_b = f"/aws/lambda/{fn_with_logs}"

    # Positive control: the properly-permissioned function's log group/stream do appear.
    streams_b = _poll_for_streams(ctx, group_b, timeout_s=60)
    assert streams_b, f"expected control function {fn_with_logs} to get log streams, got none"
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_b))

    # Negative: give group_a the same generous window; it must never materialize, and
    # describe_log_streams must fail with exactly ResourceNotFoundException.
    deadline = time.monotonic() + 30
    appeared = False
    while time.monotonic() < deadline:
        if _error_code(lambda: logs.describe_log_streams(logGroupName=group_a)) is None:
            appeared = True
            break
        time.sleep(3)
    assert not appeared, f"log group {group_a} unexpectedly appeared for a role without logs permissions"

    code = _error_code(lambda: logs.describe_log_streams(logGroupName=group_a))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"

    # --- restore: attach the missing logs permission to the SAME role that was capped
    # above, re-invoke the SAME function, and demand that the identical call now succeeds --
    # proving the earlier absence was this permission's doing, not some other block.
    iam.attach_role_policy(
        RoleName=role_name_no_logs,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    ctx.on_cleanup(lambda: _delete_log_group_quiet(ctx, group_a))
    _run_aws(ctx, "lambda", "invoke", "--function-name", fn_no_logs, "--payload", "{}", "/dev/null")
    restored_streams = _poll_for_streams(ctx, group_a, timeout_s=60)
    assert restored_streams, (
        f"attaching logs permission to {role_name_no_logs} and re-invoking {fn_no_logs} must "
        f"materialize log streams for {group_a}; got none"
    )


def _poll_for_streams(ctx, log_group, timeout_s=60, interval_s=4):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = logs.describe_log_streams(logGroupName=log_group)
            if resp.get("logStreams"):
                return resp["logStreams"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(interval_s)
    return []


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


def _delete_log_group_quiet(ctx, log_group_name):
    logs = ctx.client("logs")
    try:
        logs.delete_log_group(logGroupName=log_group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _aws_cli_available(ctx) -> bool:
    return shutil.which("aws", path=ctx.subprocess_env().get("PATH")) is not None


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
        ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _zip_bytes(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx, role_name: str, with_logs_permission: bool) -> str:
    iam = ctx.client("iam")
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
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if with_logs_permission:
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )
    return role_arn


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
        for p in attached:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_function(ctx, name, role_arn, handler_code, handler="index.handler", timeout_s=15, env_vars=None):
    lam = ctx.client("lambda")
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler=handler,
        Code={"ZipFile": _zip_bytes(handler_code)},
        Timeout=timeout_s,
        Publish=True,
        Tags={"sim2real": CHECK},
    )
    if env_vars:
        kwargs["Environment"] = {"Variables": env_vars}
    deadline = time.monotonic() + 60
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_for_active(ctx, name)
    return resp["FunctionArn"]


def _wait_for_active(ctx, name, timeout_s=60):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return
        if cfg["State"] == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg}")
        time.sleep(2)
    raise AssertionError("function never became Active")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
