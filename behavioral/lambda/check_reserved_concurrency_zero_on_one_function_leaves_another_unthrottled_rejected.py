"""reserved-concurrency-zero-on-one-function-leaves-another-unthrottled-rejected."""
from __future__ import annotations

import base64
import concurrent.futures
import io
import json
import time
import zipfile

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reserved-concurrency-zero-on-one-function-leaves-another-unthrottled-rejected"
GROUP = 'concurrency'
SERVICES = ['lambda']

_HANDLER = """\
import time
import uuid

ENV_ID = uuid.uuid4().hex


def handler(event, context):
    time.sleep(event.get("hold_s", 0))
    held = []
    for _ in range(event.get("chunks", 0)):
        block = bytearray(8 * 1024 * 1024)
        for i in range(0, len(block), 4096):
            block[i] = 1
        held.append(block)
    return {"env_id": ENV_ID, "version": context.function_version}
"""


def _zip(source):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


def _teardown(undo, *not_found):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_group(logs, name, *, reads=3, interval_s=3.0, budget_s=120.0):
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent; raise if not."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name!r} still present after {budget_s}s of deletes; "
                    f"{absent} clean reads"
                )
            time.sleep(interval_s)


def _make_role(ctx):
    """An execution role this check creates and deletes; the partition comes from its own ARN."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-l7-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    partition = arn.split(":")[1]
    policy = f"arn:{partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(_teardown(
        lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy), "NoSuchEntity"))
    return arn


def _wait_ready(lam, fn, timeout_s=180.0):
    """Poll until the function is Active with no update in flight; raise on Failed or timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed" or last.get("LastUpdateStatus") == "Failed":
            raise AssertionError(
                f"{fn} failed: {last.get('StateReason')!r} {last.get('LastUpdateStatusReason')!r}")
        if last["State"] == "Active" and last.get("LastUpdateStatus") in (None, "Successful"):
            return last
        time.sleep(1.0)
    raise AssertionError(f"{fn} never became Active/Successful in {timeout_s}s; last={last!r}")


def _create_function(ctx, lam, role_arn, source, **kwargs):
    """CreateFunction (python3.12), retried while the new role propagates; reaped in cleanup."""
    name = ctx.unique_name("sim2real-behav-l7-fn-")
    logs = ctx.client("logs")
    # Registered BEFORE the create, so LIFO runs it after the function's own delete.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + 120
    while True:
        try:
            lam.create_function(
                FunctionName=name, Runtime="python3.12", Handler="index.handler", Role=role_arn,
                Code={"ZipFile": _zip(source)}, Tags={"sim2real": CHECK}, **kwargs)
            break
        except ClientError as exc:
            # IAM propagation exposes no pollable condition; the bounded retry is the fix.
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    _wait_ready(lam, name)
    return name


def _invoker(ctx):
    """A Lambda client that never retries (a retried 429 hides the throttle) and waits long."""
    return ctx.client("lambda", config=Config(read_timeout=120, retries={"total_max_attempts": 1}))


def _invoke(lam, fn, event, **kwargs):
    """Synchronous invoke: (response, decoded body, log tail, request id)."""
    payload = event if isinstance(event, bytes) else json.dumps(event).encode()
    resp = lam.invoke(FunctionName=fn, Payload=payload, LogType="Tail", **kwargs)
    raw = resp["Payload"].read()
    try:
        body = json.loads(raw)
    except ValueError as exc:
        raise AssertionError(f"invoke returned a non-JSON body: {raw[:200]!r}") from exc
    tail = base64.b64decode(resp.get("LogResult") or b"").decode("utf-8", "replace")
    return resp, body, tail, resp["ResponseMetadata"]["RequestId"]


def _refusal(fn):
    """The ClientError ``fn`` raises, as (code, message, response). A success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message"), exc.response
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _report_line(tail, rid):
    lines = [ln for ln in tail.splitlines() if ln.startswith(f"REPORT RequestId: {rid}")]
    assert len(lines) == 1, f"expected one REPORT line for request {rid!r} in the log tail: {tail!r}"
    return lines[0]


_THROTTLE_MESSAGE = "Rate Exceeded."
_THROTTLE_REASON = "ReservedFunctionConcurrentInvocationLimitExceeded"


def _try_invoke(invoker, fn, event, qualifier=None):
    """("ok", body) or ("throttled", error response); any other failure raises."""
    kwargs = {"Qualifier": qualifier} if qualifier else {}
    try:
        resp = invoker.invoke(FunctionName=fn, Payload=json.dumps(event).encode(), **kwargs)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "TooManyRequestsException":
            return "throttled", exc.response
        raise
    return "ok", (resp.get("FunctionError"), json.loads(resp["Payload"].read()))


def _assert_reserved_throttle(err, label):
    assert err["Error"]["Code"] == "TooManyRequestsException", f"{label}: {err['Error']!r}"
    assert err["Error"].get("Message") == _THROTTLE_MESSAGE, (
        f"{label}: throttle message {err['Error'].get('Message')!r}, expected {_THROTTLE_MESSAGE!r}")
    assert err.get("Reason") == _THROTTLE_REASON, (
        f"{label}: throttle Reason {err.get('Reason')!r}, expected {_THROTTLE_REASON!r}")
    status = err["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 429, f"{label}: throttle HTTP status {status!r}, expected 429"


def _hold(invoker, fn, event, qualifier=None):
    """Invoke until admitted: a slot just released can take a moment to be reusable (bounded)."""
    deadline = time.monotonic() + 15
    while True:
        outcome, detail = _try_invoke(invoker, fn, event, qualifier)
        if outcome == "ok" or time.monotonic() > deadline:
            return outcome, detail
        time.sleep(0.2)


def _probe_while_held(invoker, fn, hold_event, hold_qualifier=None, probe_qualifier=None):
    """Hold the one slot with ``hold_event`` and probe with a no-op invoke until the probe is
    throttled or the holder returns: (holder result, first throttle response or None)."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        holder = pool.submit(_hold, invoker, fn, hold_event, hold_qualifier)
        throttle = None
        while not holder.done():
            time.sleep(0.5)
            outcome, detail = _try_invoke(invoker, fn, {}, probe_qualifier)
            if outcome == "throttled":
                throttle = detail
                break
        return holder.result(), throttle


def _reserve_one(ctx, lam, invoker, fn, hold_event):
    """ReservedConcurrentExecutions=1, then wait (bounded) until the invoke path enforces it."""
    lam.put_function_concurrency(FunctionName=fn, ReservedConcurrentExecutions=1)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function_concurrency(FunctionName=fn),
                             "ResourceNotFoundException"))
    deadline = time.monotonic() + 90
    while True:
        held, throttle = _probe_while_held(invoker, fn, hold_event)
        if throttle is not None:
            return held, throttle
        assert time.monotonic() < deadline, (
            "ReservedConcurrentExecutions=1 was never enforced: a probe beside a holding invoke "
            "always succeeded for 90 s")


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """ReservedConcurrentExecutions=0 on one function throttles only that function (429, Reason
    ReservedFunctionConcurrentInvocationLimitExceeded) while an identical sibling keeps
    answering; DeleteFunctionConcurrency readmits the first.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-concurrency.html
    """
    role = _make_role(ctx)
    lam = ctx.client("lambda")
    invoker = _invoker(ctx)
    blocked = _create_function(ctx, lam, role, _HANDLER, MemorySize=128, Timeout=10)
    sibling = _create_function(ctx, lam, role, _HANDLER, MemorySize=128, Timeout=10)

    for fn in (blocked, sibling):
        outcome, detail = _try_invoke(invoker, fn, {})
        assert outcome == "ok" and detail[0] is None, f"control invoke: {outcome!r} {detail!r}"

    reserved_at = time.monotonic()
    lam.put_function_concurrency(FunctionName=blocked, ReservedConcurrentExecutions=0)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function_concurrency(FunctionName=blocked),
                             "ResourceNotFoundException"))
    # Bounded wait for the reservation to reach the invoke path.
    deadline = time.monotonic() + 60
    while True:
        outcome, detail = _try_invoke(invoker, blocked, {})
        if outcome == "throttled":
            break
        assert time.monotonic() < deadline, "ReservedConcurrentExecutions=0 never throttled for 60 s"
        time.sleep(1.0)
    _assert_reserved_throttle(detail, "reserved=0 function")

    # The sibling stays admitted for twice as long as the reservation took to reach the invoke
    # path (at least 30 s), so a reservation that spreads to it later is still caught.
    window_end = time.monotonic() + max(30.0, 2 * (time.monotonic() - reserved_at))
    while True:
        outcome, detail = _try_invoke(invoker, sibling, {})
        assert outcome == "ok" and detail[0] is None, (
            f"the unreserved sibling was affected by another function's reservation: "
            f"{outcome!r} {detail!r}")
        if time.monotonic() >= window_end:
            break
        time.sleep(1.0)

    lam.delete_function_concurrency(FunctionName=blocked)
    assert "ReservedConcurrentExecutions" not in lam.get_function_concurrency(FunctionName=blocked), (
        "GetFunctionConcurrency still reports a reservation after DeleteFunctionConcurrency")
    deadline = time.monotonic() + 60
    while True:
        outcome, detail = _try_invoke(invoker, blocked, {})
        if outcome == "ok":
            break
        assert time.monotonic() < deadline, "the function stayed throttled 60 s after the delete"
        time.sleep(1.0)
    assert detail[0] is None, f"the readmitted invoke failed: {detail!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
