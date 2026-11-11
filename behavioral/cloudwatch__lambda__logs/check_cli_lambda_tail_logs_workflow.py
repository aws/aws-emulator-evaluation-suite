"""cli-lambda-tail-logs-workflow."""
from __future__ import annotations

import json
import subprocess
import time
import io
import zipfile

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-lambda-tail-logs-workflow"
GROUP = "cli-workflow"
SERVICES = ["cloudwatch", "lambda", "logs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """`aws lambda invoke` succeeds and `aws logs filter-log-events` then returns the line the
    function printed."""
    require_tools("aws")

    role_arn = _create_lambda_role(ctx, with_logs_permission=True)
    marker = ctx.unique_name("sim2real-tail-marker-")
    handler_code = (
        "def handler(event, context):\n"
        f"    print('MARKER::{marker}')\n"
        "    return 'ok'\n"
    )
    fn_name = ctx.unique_name("sim2real-behav-tailfn-")
    _create_function(ctx, fn_name, role_arn, handler_code)

    invoke_result = _run_aws(
        ctx,
        "lambda", "invoke",
        "--function-name", fn_name,
        "--payload", "{}",
        "/dev/null",
    )
    assert invoke_result.get("StatusCode") == 200, f"invoke did not succeed: {invoke_result}"

    log_group = f"/aws/lambda/{fn_name}"
    ctx.on_cleanup(lambda: ctx.client("logs").delete_log_group(logGroupName=log_group))
    deadline = time.monotonic() + 120
    found = False
    tail_output = ""
    tail_stderr = ""
    while time.monotonic() < deadline and not found:
        proc = _run_shell(
            ctx,
            ["aws", "logs", "filter-log-events", "--log-group-name", log_group],
            timeout_s=30,
            check=False,
        )
        tail_output = proc.stdout
        tail_stderr = proc.stderr
        if marker in tail_output:
            found = True
            break
        time.sleep(5)

    assert found, (
        f"marker {marker!r} never appeared in `aws logs filter-log-events` output: "
        f"stdout={tail_output[-500:]!r} stderr={tail_stderr[-500:]!r}"
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


def _create_lambda_role(ctx, with_logs_permission: bool) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
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
