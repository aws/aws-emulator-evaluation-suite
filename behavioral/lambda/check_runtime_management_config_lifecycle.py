"""runtime-management-config-lifecycle."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "runtime-management-config-lifecycle"
GROUP = 'function_config'
SERVICES = ['lambda']


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLES: dict = {}
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _exec_role_arn(ctx):
    """An execution role this check creates (once per run) and deletes in cleanup."""
    held = _ROLES.get(id(ctx))
    if held is not None and held[0] is ctx:
        return held[1]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lambda-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    _ROLES[id(ctx)] = (ctx, arn)
    ctx.on_cleanup(lambda: _ROLES.pop(id(ctx), None))
    return arn


def _create_function_retrying(lam, **kwargs):
    """CreateFunction, retried while the role this check just created propagates in IAM."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _cleanup_fn(ctx, lam, name):
    try:
        lam.delete_function_url_config(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_active(lam, fn, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"Function {fn} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return
        time.sleep(1.0)
    raise AssertionError(f"{fn} Active not met within {timeout_s}s. Last: {last!r}")


def _deploy_function(ctx, lam, code, *, name=None, handler="index.handler",
                     runtime="python3.12", memory=128, timeout=30, environment=None,
                     layers=None, ephemeral_storage=None, role=None):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    kwargs = {
        "FunctionName": name,
        "Runtime": runtime,
        "Handler": handler,
        "Role": role or _exec_role_arn(ctx),
        "Code": {"ZipFile": _make_zip(code)},
        "MemorySize": memory,
        "Timeout": timeout,
        "Tags": {"sim2real:managed": "true"},
    }
    if environment:
        kwargs["Environment"] = {"Variables": environment}
    if layers:
        kwargs["Layers"] = layers
    if ephemeral_storage:
        kwargs["EphemeralStorage"] = {"Size": ephemeral_storage}
    _create_function_retrying(lam, **kwargs)
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _error(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _wait_update_settled(lam, fn, timeout_s=60):
    """Poll until the function's last update reaches Successful; Failed or a timeout raises."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        status = last.get("LastUpdateStatus")
        if status == "Failed":
            raise AssertionError(f"Function {fn} update failed: {last.get('LastUpdateStatusReason')}")
        if status == "Successful":
            return last
        time.sleep(1.0)
    raise AssertionError(f"{fn} update did not settle within {timeout_s}s. Last: {last!r}")


def _call_with_retry(fn, *, retryable=("ResourceConflictException",), timeout_s=60, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in retryable:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Runtime management mode transitions between Auto/FunctionUpdate/Manual persist; Manual
    without a RuntimeVersionArn is InvalidParameterValueException, asserted only after the prior
    update settles so an in-progress update conflict cannot stand in for it.
    """
    lam = ctx.client("lambda")
    fn = _deploy_function(ctx, lam, "def handler(e, c): return e")

    def _put_runtime_config(**kwargs):
        return _call_with_retry(
            lambda: lam.put_runtime_management_config(FunctionName=fn, **kwargs)
        )

    default = lam.get_runtime_management_config(FunctionName=fn)
    assert default["UpdateRuntimeOn"] == "Auto", (
        f"expected a new function's default UpdateRuntimeOn to be Auto, got {default!r}"
    )

    to_function_update = _put_runtime_config(UpdateRuntimeOn="FunctionUpdate")
    assert to_function_update["UpdateRuntimeOn"] == "FunctionUpdate", (
        f"put_runtime_management_config(FunctionUpdate) returned {to_function_update!r}"
    )
    got1 = lam.get_runtime_management_config(FunctionName=fn)
    assert got1["UpdateRuntimeOn"] == "FunctionUpdate", (
        f"expected FunctionUpdate to persist, get_runtime_management_config returned {got1!r}"
    )

    _wait_update_settled(lam, fn)
    manual_code, manual_msg = _error(
        lambda: lam.put_runtime_management_config(FunctionName=fn, UpdateRuntimeOn="Manual")
    )
    assert manual_code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException, got {manual_code}"
    )
    expected = (
        "Missing runtime version ARN. A runtime version ARN is required when "
        "UpdateRuntimeVersionOn=Manual. Provide a valid runtime version ARN and retry the request."
    )
    assert manual_msg == expected, (
        f"PutRuntimeManagementConfig(Manual) without RuntimeVersionArn: expected message "
        f"{expected!r}, got {manual_msg!r}"
    )
    got_after_reject = lam.get_runtime_management_config(FunctionName=fn)
    assert got_after_reject["UpdateRuntimeOn"] == "FunctionUpdate", (
        "rejected PutRuntimeManagementConfig(Manual, no RuntimeVersionArn) mutated state: "
        f"expected FunctionUpdate still in effect, got {got_after_reject!r}"
    )

    runtime_arn = got1.get("RuntimeVersionArn") or lam.get_function_configuration(FunctionName=fn).get(
        "RuntimeVersionConfig", {}
    ).get("RuntimeVersionArn")
    assert runtime_arn, (
        "expected RuntimeVersionArn to be populated for a FunctionUpdate-mode zip function "
        f"once Active, got get_runtime_management_config={got1!r}"
    )
    manual = _put_runtime_config(UpdateRuntimeOn="Manual", RuntimeVersionArn=runtime_arn)
    assert manual["UpdateRuntimeOn"] == "Manual", (
        f"put_runtime_management_config(Manual, RuntimeVersionArn={runtime_arn}) returned {manual!r}"
    )
    got2 = lam.get_runtime_management_config(FunctionName=fn)
    assert got2["UpdateRuntimeOn"] == "Manual", (
        f"expected Manual to persist, get_runtime_management_config returned {got2!r}"
    )

    reverted = _put_runtime_config(UpdateRuntimeOn="Auto")
    assert reverted["UpdateRuntimeOn"] == "Auto", (
        f"put_runtime_management_config(Auto) returned {reverted!r}"
    )
    got3 = lam.get_runtime_management_config(FunctionName=fn)
    assert got3["UpdateRuntimeOn"] == "Auto", (
        f"expected Auto to persist, get_runtime_management_config returned {got3!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
