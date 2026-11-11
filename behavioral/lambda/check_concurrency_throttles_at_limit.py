"""concurrency-throttles-at-limit."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.config import Config
from botocore.exceptions import ClientError


from behavioral_harness import tags


CHECK = "concurrency-throttles-at-limit"
GROUP = 'concurrency_enforcement'
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
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
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
    _ROLES[id(ctx)] = arn
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
    }
    if environment:
        kwargs["Environment"] = {"Variables": environment}
    if layers:
        kwargs["Layers"] = layers
    if ephemeral_storage:
        kwargs["EphemeralStorage"] = {"Size": ephemeral_storage}
    kwargs["Tags"] = {"sim2real-check": CHECK}
    _create_function_retrying(lam, **kwargs)
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """With reserved concurrency 1, an invoke beside a held one is refused with 429
    TooManyRequestsException (Reason ReservedFunctionConcurrentInvocationLimitExceeded), and an
    identical invoke succeeds once the slot is free again.
    """
    lam = ctx.client("lambda")
    account_limit = lam.get_account_settings().get("AccountLimit", {})
    code = """\
import time
def handler(event, context):
    time.sleep(event.get("hold", 5))
    return {"held": True}
"""
    fn = _deploy_function(ctx, lam, code, timeout=60)
    try:
        lam.put_function_concurrency(FunctionName=fn, ReservedConcurrentExecutions=1)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException":
            raise AssertionError(
                "account posture: PutFunctionConcurrency(1) refused with account ConcurrentExecutions="
                f"{account_limit.get('ConcurrentExecutions')!r}, UnreservedConcurrentExecutions="
                f"{account_limit.get('UnreservedConcurrentExecutions')!r}; this member needs an account "
                f"quota that leaves room for one reserved execution: {exc}"
            ) from exc
        raise
    conf = lam.get_function_concurrency(FunctionName=fn)
    assert conf.get("ReservedConcurrentExecutions") == 1, (
        f"put_function_concurrency did not take effect: {conf}"
    )
    import concurrent.futures

    # botocore's default retry policy retries a 429 into a success, which would hide the very
    # throttle this check exists to observe. total_max_attempts=1 disables retries entirely.
    probe = ctx.client("lambda", config=Config(read_timeout=120, retries={"total_max_attempts": 1}))
    assert probe.meta.config.retries["total_max_attempts"] == 1, (
        f"invoke client resolved retries to {probe.meta.config.retries!r}, expected "
        "total_max_attempts == 1 (no retries at all)"
    )

    def invoke_catching(payload):
        try:
            resp = probe.invoke(FunctionName=fn, Payload=json.dumps(payload).encode())
            return ("ok", resp["StatusCode"])
        except ClientError as exc:
            return ("throttled", exc.response)

    # Positive control: a solo invoke succeeds under the same reservation.
    warm = invoke_catching({"hold": 0})
    assert warm == ("ok", 200), (
        f"a solo invoke must succeed under a still-active ReservedConcurrentExecutions=1, got {warm}"
    )

    # A holder keeps the one slot busy; no-op probes run beside it until one is refused or the
    # holder returns. The holder is re-issued until the budget runs out, so the leg never relies
    # on a guessed propagation delay.
    left = ctx.time_left()
    deadline = time.monotonic() + max(1.0, (90.0 if left is None else left) - 30.0)
    throttle = None
    holder_result = None
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        while throttle is None and time.monotonic() < deadline:
            holder = pool.submit(invoke_catching, {"hold": 6})
            while not holder.done():
                time.sleep(0.5)
                outcome, detail = invoke_catching({"hold": 0})
                if outcome == "throttled":
                    throttle = detail
                    break
            holder_result = holder.result()
            if throttle is None and holder_result[0] == "throttled":
                throttle = holder_result[1]
    if throttle is None:
        conf_now = lam.get_function_concurrency(FunctionName=fn)
        raise AssertionError(
            "no invoke beside a holder was throttled under ReservedConcurrentExecutions=1 "
            f"(last holder: {holder_result}, concurrency config now: {conf_now})"
        )

    err = throttle["Error"]
    assert err["Code"] == "TooManyRequestsException", f"throttle code: {err!r}"
    assert err.get("Message") == "Rate Exceeded.", f"throttle message: {err!r}"
    assert throttle.get("Reason") == "ReservedFunctionConcurrentInvocationLimitExceeded", (
        f"throttle Reason: {throttle.get('Reason')!r}"
    )
    assert throttle["ResponseMetadata"]["HTTPStatusCode"] == 429, throttle["ResponseMetadata"]

    # The throttle is transient: once the holder returns, the freed slot admits an identical
    # invoke under the same ReservedConcurrentExecutions=1.
    recovery = invoke_catching({"hold": 1})
    assert recovery == ("ok", 200), (
        f"invoke must succeed again once the reserved slot frees, got {recovery}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
