"""timeout-lowered-kills-a-handler-that-finished-before-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "timeout-lowered-kills-a-handler-that-finished-before-rejected"
GROUP = 'timeout'
SERVICES = ['lambda']

_LONG_S = 7
_SHORT_S = 2
#: Between the two Timeouts: finishes under the long one, killed under the short one.
_MIDDLE_SLEEP_S = 4

_HANDLER = """\
import time


def handler(event, context):
    entry = context.get_remaining_time_in_millis()
    time.sleep(event["sleep_s"])
    return {"entry_ms": entry}
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


def _reap_log_group(logs, name, *, reads=3, interval_s=3.0, budget_s=40):
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


def _wait_ready(lam, fn, timeout_s=40):
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
    deadline = time.monotonic() + 40
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
    return ctx.client("lambda", config=Config(read_timeout=40, retries={"total_max_attempts": 1}))


def _invoke(lam, fn, event, **kwargs):
    """Synchronous invoke: (response, decoded body, request id)."""
    payload = event if isinstance(event, bytes) else json.dumps(event).encode()
    resp = lam.invoke(FunctionName=fn, Payload=payload, **kwargs)
    raw = resp["Payload"].read()
    try:
        body = json.loads(raw)
    except ValueError as exc:
        raise AssertionError(f"invoke returned a non-JSON body: {raw[:200]!r}") from exc
    return resp, body, resp["ResponseMetadata"]["RequestId"]


def _assert_timed_out(resp, body, rid, timeout_s, label):
    assert resp.get("FunctionError") == "Unhandled", (
        f"{label}: FunctionError={resp.get('FunctionError')!r}, expected 'Unhandled': {body!r}")
    assert body.get("errorType") == "Sandbox.Timedout", f"{label}: errorType {body!r}"
    want = f"RequestId: {rid} Error: Task timed out after {timeout_s}.00 seconds"
    assert body.get("errorMessage") == want, (
        f"{label}: errorMessage {body.get('errorMessage')!r}, expected {want!r}")



@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Lowering Timeout with UpdateFunctionConfiguration tightens the enforced deadline: a 4 s handler
    finishes under Timeout=7 with about 7 s left at entry, and after Timeout=2 the identical invoke is
    killed "after 2.00 seconds" while a quick invoke still finishes with at most 2 s left.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-timeout.html
    """
    role = _make_role(ctx)
    lam = ctx.client("lambda")
    fn = _create_function(ctx, lam, role, _HANDLER, MemorySize=256, Timeout=_LONG_S)
    invoker = _invoker(ctx)

    resp, body, _ = _invoke(invoker, fn, {"sleep_s": _MIDDLE_SLEEP_S})
    assert resp.get("FunctionError") is None, (
        f"the {_MIDDLE_SLEEP_S} s invoke failed under Timeout={_LONG_S}: {body!r}")
    entry = body.get("entry_ms")
    assert isinstance(entry, int) and (_LONG_S - 1) * 1000 < entry <= _LONG_S * 1000, (
        f"remaining time at entry under Timeout={_LONG_S} was {entry!r} ms")

    lam.update_function_configuration(FunctionName=fn, Timeout=_SHORT_S)
    conf = _wait_ready(lam, fn)
    assert conf["Timeout"] == _SHORT_S, f"GetFunctionConfiguration Timeout={conf['Timeout']!r}"

    resp, body, rid = _invoke(invoker, fn, {"sleep_s": _MIDDLE_SLEEP_S})
    _assert_timed_out(resp, body, rid, _SHORT_S, f"sleep {_MIDDLE_SLEEP_S} s under Timeout={_SHORT_S}")

    # Positive control on the lowered wiring: a quick invoke still finishes inside the new deadline.
    ok, ok_body, _ = _invoke(invoker, fn, {"sleep_s": 0})
    assert ok.get("FunctionError") is None, f"the quick control invoke failed: {ok_body!r}"
    entry = ok_body.get("entry_ms")
    assert isinstance(entry, int) and (_SHORT_S - 1) * 1000 < entry <= _SHORT_S * 1000, (
        f"remaining time at entry under Timeout={_SHORT_S} was {entry!r} ms")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
