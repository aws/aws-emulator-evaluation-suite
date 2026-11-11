"""concurrent-function-update-conflict."""

from __future__ import annotations

import io
import os
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError


from behavioral_harness import tags


CHECK = "concurrent-function-update-conflict"
GROUP = 'concurrency'
SERVICES = ['lambda']

HANDLER_V1 = "def handler(event, context): return {'marker': 'v1', 'echo': event}"
HANDLER_V2 = "def handler(event, context): return {'marker': 'v2', 'echo': event}"
_ARM_ATTEMPTS = 3


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


def _make_padded_zip(code, pad_mb=10):
    """A padded (ZIP_STORED + incompressible bytes) package widens the real window during which a
    just-issued UpdateFunctionCode stays Pending/InProgress, so a concurrently issued
    UpdateFunctionConfiguration has a realistic chance of colliding with it."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("index.py", textwrap.dedent(code))
        zf.writestr("padding.bin", os.urandom(pad_mb * 1024 * 1024))
    return buf.getvalue()


_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLES: dict = {}


def _role_arn(ctx):
    """Create this check's own Lambda execution role once per run and register its cleanup."""
    import json as _json

    held = _ROLES.get(id(ctx))
    if held is not None and held[0] is ctx:
        return held[1]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY))
    _ROLES[id(ctx)] = (ctx, arn)
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retrying only while a freshly created role is not yet assumable."""
    from botocore.exceptions import ClientError as _ClientError

    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except _ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = err.get("Code") == "InvalidParameterValueException" and "cannot be assumed" in err.get("Message", "")
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(3)


def _cleanup_fn(ctx, lam, name):
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


def _budget(ctx, cap_s, reserve_s=5.0):
    """A wait's cap, cut to the runner's remaining time so the check fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - reserve_s))


def _wait_active(ctx, lam, fn, timeout_s=60):
    timeout_s = _budget(ctx, timeout_s)
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


def _wait_update_settled(ctx, lam, fn, timeout_s=90):
    deadline = time.monotonic() + _budget(ctx, timeout_s)
    while time.monotonic() < deadline:
        status = lam.get_function_configuration(FunctionName=fn).get("LastUpdateStatus")
        if status in ("Successful", "Failed", None):
            return
        time.sleep(1.0)


def _deploy_function(ctx, lam, code, *, name=None):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    _create_function(lam, 
        FunctionName=name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=_role_arn(ctx),
        Code={"ZipFile": _make_zip(code)},
        MemorySize=128,
        Timeout=30,
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(ctx, lam, name)
    return name


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second update issued while the function is still Pending/InProgress gets ResourceConflictException.

    A configuration mutation issued while a function's previous UpdateFunctionCode is still
    Pending/InProgress fails with ResourceConflictException — only one mutation may be in flight at once.
    """
    lam = ctx.client("lambda")
    fn = _deploy_function(ctx, lam, HANDLER_V1)

    # Positive control: an uncontested UpdateFunctionConfiguration succeeds on its own, so a
    # later rejection can be attributed to the induced conflict rather than to a broken account,
    # role or function.
    lam.update_function_configuration(FunctionName=fn, Description="positive-control")
    _wait_update_settled(ctx, lam, fn)
    control_cfg = lam.get_function_configuration(FunctionName=fn)
    assert control_cfg.get("Description") == "positive-control", control_cfg

    # A padded (~10MB) deployment package widens the real window during which
    # LastUpdateStatus stays Pending/InProgress after UpdateFunctionCode. The conflicting update
    # follows at once; one accepted because the code update had already settled is reverted and
    # the leg re-armed.
    refusal = None
    for _ in range(_ARM_ATTEMPTS):
        lam.update_function_code(FunctionName=fn, ZipFile=_make_padded_zip(HANDLER_V2, pad_mb=10))
        try:
            lam.update_function_configuration(FunctionName=fn, Timeout=20)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            refusal = (err.get("Code"), err.get("Message"))
            break
        _wait_update_settled(ctx, lam, fn)
        lam.update_function_configuration(FunctionName=fn, Timeout=30)
        _wait_update_settled(ctx, lam, fn)
        if _budget(ctx, 60.0, 0.0) < 30.0:
            break
    assert refusal is not None, (
        f"a configuration update issued right after a padded UpdateFunctionCode was accepted in "
        f"each of {_ARM_ATTEMPTS} attempts; it must be refused while the code update is in progress"
    )
    code, message = refusal
    assert code == "ResourceConflictException", f"expected ResourceConflictException, got {code}"
    fn_arn = lam.get_function_configuration(FunctionName=fn)["FunctionArn"]
    expected_message = (
        f"The operation cannot be performed at this time. An update is in progress for resource: {fn_arn}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    _wait_update_settled(ctx, lam, fn)
    settled_cfg = lam.get_function_configuration(FunctionName=fn)
    assert settled_cfg["State"] == "Active", settled_cfg
    assert settled_cfg["Timeout"] == 30, (
        "a rejected UpdateFunctionConfiguration must have had zero effect; expected the "
        f"original Timeout=30 (unchanged), got {settled_cfg.get('Timeout')}"
    )

    # Restore: once the colliding code update has settled, the identical config mutation
    # is no longer blocked and must now succeed.
    lam.update_function_configuration(FunctionName=fn, Timeout=20)
    _wait_update_settled(ctx, lam, fn)
    restored_cfg = lam.get_function_configuration(FunctionName=fn)
    assert restored_cfg["Timeout"] == 20, (
        "the identical UpdateFunctionConfiguration call must succeed once the conflicting "
        f"update has settled; expected Timeout=20, got {restored_cfg.get('Timeout')}"
    )
    assert restored_cfg["State"] == "Active", restored_cfg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
