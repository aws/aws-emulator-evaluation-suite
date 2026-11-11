"""invoke-async-fire-and-forget-managed."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invoke-async-fire-and-forget-managed"
GROUP = "server-side"
SERVICES = ["lambda"]

_SLEEP_SECONDS = 10
# Well under the handler sleep, so a synchronous run cannot pass, and wide enough for a loaded host.
_RETURN_BOUND_S = 5.0

_HANDLER_PY = (
    "import json\n"
    "import time\n\n"
    "def handler(event, context):\n"
    "    time.sleep(event.get('sleep_seconds', 5))\n"
    "    print('ASYNC_MARKER:' + event.get('marker', ''))\n"
    "    return {'ok': True}\n"
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeAsync returns HTTP 202 immediately while the managed service runs the function
    to completion in the background, well after the call has already returned."""
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    try:
        role_arn = _create_basic_execution_role(ctx, iam)
        function_name = ctx.unique_name("sim2real-behav-asyncfn-")
        code_zip = _make_zip({"lambda_function.py": _HANDLER_PY})
        _create_function_with_retry(
            ctx,
            lam,
            FunctionName=function_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": code_zip},
            Timeout=30,
            MemorySize=128,
        )
        ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
        _wait_for_active(lam, function_name)
    except AssertionError:
        raise
    except Exception as exc:  # noqa: BLE001 - environment/prerequisite failure
        raise AssertionError(f"unreachable: could not provision function for InvokeAsync: {exc}") from exc

    marker = ctx.unique_name("marker-")
    log_group = f"/aws/lambda/{function_name}"
    payload = json.dumps({"marker": marker, "sleep_seconds": _SLEEP_SECONDS}).encode()

    # A warm call first, so the timed call below measures InvokeAsync and not first-call setup.
    warm = json.dumps({"marker": ctx.unique_name("warm-"), "sleep_seconds": 0}).encode()
    lam.invoke_async(FunctionName=function_name, InvokeArgs=warm)

    t0 = time.monotonic()
    resp = lam.invoke_async(FunctionName=function_name, InvokeArgs=payload)
    t1 = time.monotonic()

    assert resp["Status"] == 202, f"expected InvokeAsync Status 202, got {resp.get('Status')}"
    call_duration = t1 - t0
    assert call_duration < _RETURN_BOUND_S, (
        f"InvokeAsync took {call_duration:.3f}s to return - it should return immediately "
        f"without waiting for the {_SLEEP_SECONDS}s function execution"
    )

    # Immediately after the call returns, the (10s-sleeping) function cannot have finished
    # yet, so the completion marker must not already be visible in the logs.
    assert not _marker_present(logs, log_group, marker), (
        "completion marker was already visible immediately after InvokeAsync returned - "
        "the function ran synchronously instead of in the background"
    )

    _poll_until(
        lambda: _marker_present(logs, log_group, marker),
        lambda present: present,
        timeout_s=_budget_s(ctx, _SLEEP_SECONDS + 30.0),
        interval_s=1.0,
        description=f"completion marker {marker} appearing in {log_group} after background execution",
        ctx=ctx,
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _create_basic_execution_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-behav-asyncrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Role"]["Arn"]


def _create_function_with_retry(ctx, lam, **kwargs):
    last_exc = None
    for _ in range(10):
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("InvalidParameterValueException", "ResourceConflictException"):
                last_exc = exc
                time.sleep(3)
                continue
            raise
    raise last_exc


def _wait_for_active(lam, name: str, timeout_s: float = 120.0) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            return cfg
        if cfg.get("State") == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg.get('StateReason')}")
        time.sleep(2)
    raise AssertionError(f"function {name} did not become Active within {timeout_s}s")


def _marker_present(logs, log_group: str, marker: str) -> bool:
    try:
        resp = logs.filter_log_events(logGroupName=log_group, filterPattern=f'"{marker}"')
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return False
        raise
    return any(marker in e.get("message", "") for e in resp.get("events", []))


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str = "condition", ctx=None):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    if predicate(result):
        return result
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s (last={result!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
