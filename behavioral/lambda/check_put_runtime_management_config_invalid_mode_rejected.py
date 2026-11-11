"""put-runtime-management-config-invalid-mode-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any, Callable, Optional

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-runtime-management-config-invalid-mode-rejected"
GROUP = "overly-permissive"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The service itself rejects an UpdateRuntimeOn outside {Auto, Manual, FunctionUpdate} with
    ValidationException, leaving the previously accepted mode unchanged.
    """
    role_arn = _create_execution_role(ctx)
    function_name = _create_basic_function(ctx, role_arn)
    lam = ctx.client("lambda")

    # Positive control: a supported mode is accepted and read back, giving the effect-absent
    # check a baseline.
    _put_runtime_management_config_retrying(lam, function_name, "FunctionUpdate")
    baseline = lam.get_runtime_management_config(FunctionName=function_name)
    assert baseline["UpdateRuntimeOn"] == "FunctionUpdate"

    # botocore validates the enum client-side; disable that so "Bogus" reaches the service.
    unvalidated_lam = ctx.client("lambda", config=Config(parameter_validation=False))
    code, msg = _error(
        lambda: unvalidated_lam.put_runtime_management_config(
            FunctionName=function_name, UpdateRuntimeOn="Bogus"
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert msg == (
        "1 validation error detected: Value 'Bogus' at 'updateRuntimeOn' failed to satisfy constraint: "
        "Member must satisfy enum value set: [FunctionUpdate, Manual, Auto]"
    ), f"expected the exact invalid-mode message, got {msg!r}"

    # Effect absent: the rejected call did not change the mode set by the positive control.
    after = lam.get_runtime_management_config(FunctionName=function_name)
    assert after["UpdateRuntimeOn"] == "FunctionUpdate", (
        f"rejected PutRuntimeManagementConfig changed state: {after!r}"
    )


def _put_runtime_management_config_retrying(lam: Any, function_name: str, mode: str) -> None:
    """Lambda answers ResourceConflictException while the function's create/update is
    still settling, even after State == Active; retry within a bounded window."""
    deadline = time.monotonic() + 60.0
    last_exc: Optional[ClientError] = None
    while time.monotonic() < deadline:
        try:
            lam.put_runtime_management_config(FunctionName=function_name, UpdateRuntimeOn=mode)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceConflictException":
                last_exc = exc
                time.sleep(2)
                continue
            raise
    raise AssertionError(f"put_runtime_management_config kept conflicting: {last_exc}")


def _error(fn: Callable[[], Any]) -> tuple:
    """Run *fn*, which AWS must refuse; return the refusal's (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def _create_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": "runtime-mgmt-invalid-mode"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _zip_bytes(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    return buf.getvalue()


def _create_basic_function(ctx, role_arn: str) -> str:
    lam = ctx.client("lambda")
    function_name = ctx.unique_name("sim2real-lambda-fn-")
    code_bytes = _zip_bytes("def handler(event, context):\n    return {'ok': True}\n")

    deadline = time.monotonic() + 30.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": code_bytes},
                Timeout=10,
                MemorySize=128,
                Tags={"sim2real": "runtime-mgmt-invalid-mode"},
            )
            last_exc = None
            break
        except Exception as exc:  # role propagation delay
            last_exc = exc
            time.sleep(2)
    if last_exc is not None:
        raise last_exc

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))

    waiter = lam.get_waiter("function_active_v2")
    waiter.wait(FunctionName=function_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return function_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
