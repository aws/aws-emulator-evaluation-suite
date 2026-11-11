"""memory-size-bounds-rejected-and-accepted."""

from __future__ import annotations

import json
import time
import zipfile
import io

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "memory-size-bounds-rejected-and-accepted"
GROUP = "configuration_bounds"
SERVICES = ["lambda"]

# Lambda's documented MemorySize floor, in MB. The ceiling is an account quota (new accounts can
# hold a reduced one), so it is not asserted here.
_MIN = 128
_RAISED = 256

_HANDLER = 'def handler(event, context):\n    return event\n'


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateFunction and UpdateFunctionConfiguration accept MemorySize at its 128 MB floor and
    refuse one MB under it with the exact validation message, creating nothing and leaving the
    live function's MemorySize unchanged.
    """
    lam = ctx.client("lambda")
    # Client-side range validation would stop a bad value before it reaches the network; disabling
    # it is the only way to observe what the service itself does with an out-of-range value.
    lam_noval = ctx.client("lambda", config=Config(parameter_validation=False))
    iam = ctx.client("iam")
    role_arn = _create_execution_role(ctx, iam)

    fn = ctx.unique_name("sim2real-behav-memsz-")
    created = _create_function(ctx, lam, FunctionName=fn, Role=role_arn, MemorySize=_MIN)
    assert created["MemorySize"] == _MIN, (
        f"CreateFunction with the lower bound MemorySize={_MIN} must be accepted as-is, "
        f"got {created['MemorySize']!r}"
    )
    cfg = _wait_ready(ctx, lam, fn)
    assert cfg["MemorySize"] == _MIN, f"settled MemorySize expected {_MIN}, got {cfg['MemorySize']!r}"

    updated = lam.update_function_configuration(FunctionName=fn, MemorySize=_RAISED)
    assert updated["MemorySize"] == _RAISED, (
        f"UpdateFunctionConfiguration with MemorySize={_RAISED} must be accepted, "
        f"got {updated['MemorySize']!r}"
    )
    cfg = _wait_ready(ctx, lam, fn)
    assert cfg["MemorySize"] == _RAISED, (
        f"settled MemorySize expected {_RAISED}, got {cfg['MemorySize']!r}"
    )

    low = _MIN - 1
    expected = (
        f"1 validation error detected: Value '{low}' at 'memorySize' failed to satisfy "
        f"constraint: Member must have value greater than or equal to {_MIN}"
    )

    # CreateFunction refuses one MB under the floor and creates nothing.
    below_name = ctx.unique_name("sim2real-behav-memsz-low-")
    ctx.on_cleanup(
        _teardown(lambda: lam.delete_function(FunctionName=below_name), "ResourceNotFoundException")
    )
    code, msg = _error(lambda: _create_call(lam_noval, below_name, role_arn, MemorySize=low))
    assert code == "ValidationException", f"MemorySize={low} at create must be refused, got {code!r}"
    assert msg == expected, f"unexpected validation message for MemorySize={low} at create: {msg!r}"
    code, msg = _error(lambda: lam.get_function_configuration(FunctionName=below_name))
    assert code == "ResourceNotFoundException", (
        f"a refused create must leave no function; GetFunctionConfiguration gave {code!r} {msg!r}"
    )

    # UpdateFunctionConfiguration refuses the same value on the live function, unchanged.
    code, msg = _error(
        lambda: lam_noval.update_function_configuration(FunctionName=fn, MemorySize=low)
    )
    assert code == "ValidationException", f"MemorySize={low} at update must be refused, got {code!r}"
    assert msg == expected, f"unexpected validation message for MemorySize={low} at update: {msg!r}"
    cfg = lam.get_function_configuration(FunctionName=fn)
    assert cfg["MemorySize"] == _RAISED, (
        f"a refused update must not change MemorySize; expected {_RAISED}, got {cfg['MemorySize']!r}"
    )


# ===== helpers =====


def _zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _error(fn) -> tuple[str, str]:
    """``(code, message)`` of the ClientError ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {str(result)[:400]}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_execution_role(ctx, iam) -> str:
    """This check's own execution role — nothing pre-existing in the account is assumed."""
    role_name = ctx.unique_name("sim2real-behav-memsz-role-")
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
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        _teardown(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn), "NoSuchEntity")
    )
    return role["Role"]["Arn"]


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _retry_role(ctx, call):
    """Run ``call()``, retrying only Lambda's role-propagation refusal, up to 120 s of budget."""
    timeout_s = _budget_s(ctx, 120.0)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") != "InvalidParameterValueException" or "cannot be assumed" not in err.get(
                "Message", ""
            ):
                raise
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"the execution role was not assumable within {timeout_s:.0f}s: {exc}"
                ) from exc
            time.sleep(2)


def _reap_log_group(ctx, fn: str) -> None:
    """Registered BEFORE the function exists, so LIFO runs it AFTER delete_function.

    delete_function does not remove /aws/lambda/<fn>, and a buffered stream can flush after the
    delete and recreate the group, so this re-deletes until several consecutive reads find it gone.
    """
    group = f"/aws/lambda/{fn}"

    def _reap() -> None:
        logs = ctx.client("logs")
        deadline = time.monotonic() + 45.0
        absent = 0
        while absent < 3:
            groups = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
            if any(g["logGroupName"] == group for g in groups):
                absent = 0
                try:
                    logs.delete_log_group(logGroupName=group)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
            else:
                absent += 1
            if absent < 3:
                if time.monotonic() > deadline:
                    raise AssertionError(f"log group {group} still present after 45s of deletes")
                time.sleep(3)

    ctx.on_cleanup(_reap)


def _create_call(lam, name: str, role_arn: str, **overrides):
    kwargs = dict(
        FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _zip({"index.py": _HANDLER})}, Timeout=30, MemorySize=128,
        Tags={"sim2real": CHECK},
    )
    kwargs.update(overrides)
    return lam.create_function(**kwargs)


def _create_function(ctx, lam, *, FunctionName: str, Role: str, **overrides) -> dict:
    """CreateFunction, retrying only the documented role-propagation refusal."""
    _reap_log_group(ctx, FunctionName)
    created = _retry_role(ctx, lambda: _create_call(lam, FunctionName, Role, **overrides))
    ctx.on_cleanup(
        _teardown(lambda: lam.delete_function(FunctionName=FunctionName), "ResourceNotFoundException")
    )
    return created


def _wait_ready(ctx, lam, name: str, timeout_s: float = 180.0) -> dict:
    """Poll until State=Active and the last update is Successful; a Failed state raises."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    cfg: dict = {}
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed" or cfg.get("LastUpdateStatus") == "Failed":
            raise AssertionError(
                f"{name} failed: State={cfg.get('State')!r} {cfg.get('StateReason')!r} "
                f"LastUpdateStatus={cfg.get('LastUpdateStatus')!r} {cfg.get('LastUpdateStatusReason')!r}"
            )
        if cfg.get("State") == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            return cfg
        time.sleep(2)
    raise TimeoutError(f"{name} not ready within {timeout_s:.0f}s; last saw {cfg.get('State')!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
