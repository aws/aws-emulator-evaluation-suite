"""invoke-async-invalid-qualifier-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any, Callable, Optional

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "invoke-async-invalid-qualifier-rejected"
GROUP = "overly-permissive"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeAsync against a function-name:qualifier that encodes a version number which
    was never published fails with ResourceNotFoundException instead of being silently
    accepted and the invocation dropped."""
    role_arn = _create_execution_role(ctx)
    function_name = _create_basic_function(ctx, role_arn)

    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    bogus_qualified_name = f"{function_name}:999999"

    def _attempt() -> None:
        lam.invoke_async(FunctionName=bogus_qualified_name, InvokeArgs=json.dumps({"ping": "pong"}))

    code, message = _error_code(_attempt)
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent version qualifier, got {code!r}"
    )
    assert message == f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{bogus_qualified_name}", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {message!r}"
    )

    # Positive control: the identical call against the real, existing $LATEST qualifier is
    # accepted at the API boundary AND actually dispatched — proved independently by reading
    # the function's own CloudWatch Logs, not by trusting InvokeAsync's own response.
    marker = ctx.unique_name("marker-")
    accepted = lam.invoke_async(FunctionName=function_name, InvokeArgs=json.dumps({"marker": marker}))
    assert accepted["Status"] == 202, f"InvokeAsync against a valid function must be accepted, got {accepted!r}"

    log_group = f"/aws/lambda/{function_name}"
    found = _poll_until(
        lambda: _marker_present(logs, log_group, marker),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert found, (
        f"marker {marker!r} never appeared in {log_group} - InvokeAsync against the valid "
        f"$LATEST qualifier returned success but the invocation was never actually dispatched"
    )


def _error_code(fn: Callable[[], Any]) -> tuple[Optional[str], Optional[str]]:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError("the call was expected to be rejected, but it succeeded")


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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
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
    code_bytes = _zip_bytes(
        "def handler(event, context):\n"
        "    print('ASYNC_QUALIFIER_MARKER:' + event.get('marker', ''))\n"
        "    return {'ok': True}\n"
    )

    deadline = time.monotonic() + 30.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": code_bytes},
                Timeout=10,
                MemorySize=128,
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


def _marker_present(logs, log_group: str, marker: str) -> bool:
    from botocore.exceptions import ClientError

    try:
        resp = logs.filter_log_events(logGroupName=log_group, filterPattern=f'"{marker}"')
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return False
        raise
    return any(marker in e.get("message", "") for e in resp.get("events", []))


def _poll_until(probe: Callable[[], bool], *, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while True:
        if probe():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval_s)


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
