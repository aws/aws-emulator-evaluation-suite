"""runtime-management-config-roundtrip."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "runtime-management-config-roundtrip"
GROUP = "state-machine"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Default runtime management mode is overridable via Put and persists on subsequent Get."""
    lam = ctx.client("lambda")
    fn = _create_basic_function(ctx)
    _wait_function_updated(ctx, fn["name"])

    default_cfg = lam.get_runtime_management_config(FunctionName=fn["name"])
    assert default_cfg["UpdateRuntimeOn"] == "Auto", (
        f"default UpdateRuntimeOn is {default_cfg['UpdateRuntimeOn']!r}, expected 'Auto'"
    )

    put = _put_runtime_management_config_retrying(ctx, fn["name"], "FunctionUpdate")
    assert put["UpdateRuntimeOn"] == "FunctionUpdate", (
        f"PutRuntimeManagementConfig(FunctionUpdate) echoed {put['UpdateRuntimeOn']!r}"
    )

    got = lam.get_runtime_management_config(FunctionName=fn["name"])
    assert got["UpdateRuntimeOn"] == "FunctionUpdate", "PutRuntimeManagementConfig did not persist"

    reverted = _put_runtime_management_config_retrying(ctx, fn["name"], "Auto")
    assert reverted["UpdateRuntimeOn"] == "Auto", (
        f"PutRuntimeManagementConfig(Auto) echoed {reverted['UpdateRuntimeOn']!r}"
    )

    got_after_revert = lam.get_runtime_management_config(FunctionName=fn["name"])
    assert got_after_revert["UpdateRuntimeOn"] == "Auto", (
        f"revert to Auto did not persist, GetRuntimeManagementConfig returned "
        f"{got_after_revert['UpdateRuntimeOn']!r}"
    )


def _lambda_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", "def handler(event, context):\n    return {'ok': True}\n")
    return buf.getvalue()


def _create_exec_role(ctx) -> str:
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Role"]["Arn"]


def _create_basic_function(ctx) -> dict:
    lam = ctx.client("lambda")
    role_arn = _create_exec_role(ctx)
    name = ctx.unique_name("sim2real-behav-fn-")
    deadline = time.monotonic() + 90
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": _lambda_zip_bytes()},
                Timeout=10,
                MemorySize=128,
                Publish=False,
                Tags={"sim2real:managed": "true"},
            )
            break
        except Exception as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValueException" in str(e):
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError("create_function never succeeded (role propagation timeout)")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_function_active(ctx, name)
    return {"name": name, "arn": resp["FunctionArn"], "role_arn": role_arn}


def _wait_function_active(ctx, name: str) -> dict:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + 90
    cfg = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return cfg
        if cfg["State"] == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg.get('StateReason')}")
        time.sleep(2)
    raise AssertionError(f"function did not become Active in time (last={cfg!r})")


def _wait_function_updated(ctx, name: str) -> dict:
    """Wait until the function's last update has settled (LastUpdateStatus == Successful).

    Lambda rejects mutating config calls (e.g. PutRuntimeManagementConfig) with
    ResourceConflictException while a create/update operation is still in progress,
    even after the function reports State == Active.
    """
    lam = ctx.client("lambda")
    deadline = time.monotonic() + 90
    cfg = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        status = cfg.get("LastUpdateStatus")
        if status == "Successful":
            return cfg
        if status == "Failed":
            raise AssertionError(f"function last update failed: {cfg.get('LastUpdateStatusReason')}")
        time.sleep(2)
    raise AssertionError(f"function last update did not settle in time (last={cfg!r})")


def _put_runtime_management_config_retrying(ctx, name: str, mode: str) -> dict:
    """PutRuntimeManagementConfig can transiently fail with ResourceConflictException
    while the function is mid-update; poll/retry within a bounded window."""
    from botocore.exceptions import ClientError

    lam = ctx.client("lambda")
    deadline = time.monotonic() + 90
    last_error = None
    while time.monotonic() < deadline:
        try:
            return lam.put_runtime_management_config(FunctionName=name, UpdateRuntimeOn=mode)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceConflictException":
                last_error = e
                time.sleep(2)
                continue
            raise
    raise AssertionError(f"put_runtime_management_config kept conflicting: {last_error}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
