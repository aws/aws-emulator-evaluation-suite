"""update-function-event-invoke-config-partial-update."""
from __future__ import annotations

import io
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-function-event-invoke-config-partial-update"
GROUP = "state-machine"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """UpdateFunctionEventInvokeConfig only overwrites the fields it specifies,
    leaving previously-configured fields (that are omitted from the call) intact."""
    lam = ctx.client("lambda")
    role_arn = _create_basic_role(ctx)
    name = ctx.unique_name("sim2real-eic-")
    zip_bytes = _zip_from_source("lambda_function.py", _BASIC_HANDLER)
    _create_function_with_retry(ctx, name=name, role_arn=role_arn, zip_bytes=zip_bytes)

    lam.put_function_event_invoke_config(
        FunctionName=name,
        MaximumRetryAttempts=2,
        MaximumEventAgeInSeconds=1800,
    )
    before = lam.get_function_event_invoke_config(FunctionName=name)
    assert before["MaximumRetryAttempts"] == 2, (
        f"expected MaximumRetryAttempts=2 after put, got {before['MaximumRetryAttempts']}"
    )
    assert before["MaximumEventAgeInSeconds"] == 1800, (
        f"expected MaximumEventAgeInSeconds=1800 after put, got {before['MaximumEventAgeInSeconds']}"
    )

    # Only touch MaximumRetryAttempts; MaximumEventAgeInSeconds is omitted.
    lam.update_function_event_invoke_config(FunctionName=name, MaximumRetryAttempts=0)

    after = lam.get_function_event_invoke_config(FunctionName=name)
    assert after["MaximumRetryAttempts"] == 0, "the field that was updated must reflect the new value"
    assert after["MaximumEventAgeInSeconds"] == 1800, (
        "UpdateFunctionEventInvokeConfig must not reset fields that were not "
        f"specified in the request; got {after['MaximumEventAgeInSeconds']}"
    )


_BASIC_HANDLER = "def lambda_handler(event, context):\n    return {'ok': True, 'event': event}\n"


def _zip_from_source(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_basic_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    import json

    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = resp["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_function_with_retry(
    ctx: Any,
    *,
    name: str,
    role_arn: str,
    zip_bytes: bytes,
    handler: str = "lambda_function.lambda_handler",
    runtime: str = "python3.12",
    timeout_s: float = 90.0,
) -> str:
    from botocore.exceptions import ClientError

    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    resp = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime=runtime,
                Role=role_arn,
                Handler=handler,
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                MemorySize=128,
                Tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as exc:
            last_exc = exc
            code = exc.response["Error"]["Code"]
            if code == "InvalidParameterValueException" and "role" in str(exc).lower():
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError(f"could not create function after retries: {last_exc}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    cfg = _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c["State"] in ("Active", "Failed"),
        timeout_s=90.0,
        interval_s=2.0,
    )
    if cfg["State"] != "Active":
        raise AssertionError(f"function failed to activate: {cfg.get('StateReason')}")
    return resp["FunctionArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
