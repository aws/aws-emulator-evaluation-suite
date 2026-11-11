"""init-past-the-init-limit-is-retried-inside-the-invoke-and-timed-out-rejected."""
from __future__ import annotations

import base64
import io
import json
import time
import zipfile

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "init-past-the-init-limit-is-retried-inside-the-invoke-and-timed-out-rejected"
GROUP = 'timeout'
SERVICES = ['lambda']

_TIMEOUT_S = 3
#: Module-level work past the 10 s init limit.
_INIT_SLEEP_S = 12

_HANDLER = """\
import os
import time

time.sleep(float(os.environ["SIM2REAL_INIT_SLEEP_S"]))


def handler(event, context):
    return {"ok": True}
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


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Module-level initialisation past the 10 s init limit is cut off and retried inside the
    first invocation under the function's Timeout, so that invoke fails with Sandbox.Timedout
    "Task timed out after 3.00 seconds"; restoring a short init lets the identical invoke through.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtime-environment.html
    """
    role = _make_role(ctx)
    lam = ctx.client("lambda")
    invoker = _invoker(ctx)
    fn = _create_function(
        ctx, lam, role, _HANDLER, MemorySize=128, Timeout=_TIMEOUT_S,
        Environment={"Variables": {"SIM2REAL_INIT_SLEEP_S": "0"}})

    # Positive control: the same code with a short init answers.
    ok, ok_body, _, _ = _invoke(invoker, fn, {})
    assert ok.get("FunctionError") is None and ok_body == {"ok": True}, (
        f"control invoke failed: {ok.get('FunctionError')!r} {ok_body!r}")

    # Break one thing: the init now outlasts the init limit.
    lam.update_function_configuration(
        FunctionName=fn, Environment={"Variables": {"SIM2REAL_INIT_SLEEP_S": str(_INIT_SLEEP_S)}})
    _wait_ready(lam, fn)
    resp, body, _, rid = _invoke(invoker, fn, {})
    assert resp.get("FunctionError") == "Unhandled", (
        f"a {_INIT_SLEEP_S} s init returned FunctionError={resp.get('FunctionError')!r}: {body!r}")
    assert body.get("errorType") == "Sandbox.Timedout", f"errorType: {body!r}"
    want = f"RequestId: {rid} Error: Task timed out after {_TIMEOUT_S}.00 seconds"
    assert body.get("errorMessage") == want, (
        f"errorMessage {body.get('errorMessage')!r}, expected {want!r}")

    # Restore: the short init again, and the identical invoke succeeds.
    lam.update_function_configuration(
        FunctionName=fn, Environment={"Variables": {"SIM2REAL_INIT_SLEEP_S": "0"}})
    _wait_ready(lam, fn)
    back, back_body, _, _ = _invoke(invoker, fn, {})
    assert back.get("FunctionError") is None and back_body == {"ok": True}, (
        f"after restoring a short init the invoke still failed: {back_body!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
