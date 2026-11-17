"""reserved-concurrency-zero-invoke-reason-dry-run-bypass-restore."""

from __future__ import annotations

import base64
import json
import io
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "reserved-concurrency-zero-invoke-reason-dry-run-bypass-restore"
GROUP = "concurrency_enforcement"
SERVICES = ["lambda"]

_THROTTLE = ("TooManyRequestsException", "Rate Exceeded.")
_THROTTLE_REASON = "ReservedFunctionConcurrentInvocationLimitExceeded"

_HANDLER = """\
def handler(event, context):
    print("MARKER:" + event.get("marker", ""))
    return {"marker": event.get("marker", "")}
"""


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLES: dict = {}
_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _role_arn(ctx) -> str:
    """An execution role this check creates (once per run) and deletes in cleanup."""
    held = _ROLES.get(id(ctx))
    if held is not None and held[0] is ctx:
        return held[1]
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
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC_POLICY))
    _ROLES[id(ctx)] = (ctx, arn)
    return arn


def _create_function(lam, **kwargs):
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
    """Run every delete; only an already-absent resource is tolerated, anything else is raised
    naming the step after the others have run."""
    steps = [
        ("DeleteFunction", lambda: lam.delete_function(FunctionName=name)),
        ("DeleteLogGroup",
         lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")),
    ]
    failed = []
    for label, step in steps:
        try:
            step()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                failed.append(f"{label}: {exc}")
    if failed:
        raise RuntimeError(f"cleanup of {name} failed: {'; '.join(failed)}")


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


def _deploy_function(ctx, lam, code):
    name = ctx.unique_name("sim2real-behav-fn-")
    _create_function(
        lam,
        FunctionName=name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=_role_arn(ctx),
        Code={"ZipFile": _make_zip(code)},
        MemorySize=128,
        Timeout=30,
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _marker_present(logs, log_group, marker):
    """Whether any event in the group carries ``marker``, over every FilterLogEvents page."""
    kwargs = {"logGroupName": log_group, "filterPattern": f'"{marker}"'}
    while True:
        try:
            resp = logs.filter_log_events(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return False
            raise
        if any(marker in e.get("message", "") for e in resp.get("events", [])):
            return True
        token = resp.get("nextToken")
        if not token:
            return False
        kwargs["nextToken"] = token


def _poll_marker(logs, log_group, marker, timeout_s):
    """Seconds until ``marker`` appears in ``log_group``, or ``None`` if it never does."""
    deadline = time.monotonic() + timeout_s
    start = time.monotonic()
    while time.monotonic() < deadline:
        if _marker_present(logs, log_group, marker):
            return time.monotonic() - start
        time.sleep(1.0)
    return None


def _held_absent(logs, log_group, marker, hold_s):
    """Poll for ``marker`` over ``hold_s``; return True if it stayed absent throughout."""
    deadline = time.monotonic() + hold_s
    while time.monotonic() < deadline:
        if _marker_present(logs, log_group, marker):
            return False
        time.sleep(1.0)
    return True


def expect_error(fn, code, message, reason=None):
    """Assert ``fn()`` raises exactly ``(code, message)``, and ``reason`` if given.

    Returns the full error body so the caller can inspect fields beyond code/message.
    Raises on an unexpected success: a falsy sentinel would read as a code mismatch instead
    of the far stronger signal that the call was wrongly accepted.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        if reason is not None:
            got_reason = exc.response.get("Reason")
            assert got_reason == reason, f"expected Reason {reason!r}, got {got_reason!r}"
        assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 429, (
            f"expected HTTP 429, got {exc.response['ResponseMetadata']['HTTPStatusCode']}"
        )
        return exc.response
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


def _invoke_until_refused(lam, fn, marker_fn, timeout_s=60.0):
    """Invoke until the call is refused; return (ClientError, marker of the refused call).

    PutFunctionConcurrency(0) is applied with a short propagation lag on real AWS, so an invoke
    issued right after it can still run. A call that keeps succeeding past *timeout_s* raises as
    an unexpected success."""
    deadline = time.monotonic() + timeout_s
    while True:
        marker = marker_fn()
        try:
            result = lam.invoke(FunctionName=fn, Payload=json.dumps({"marker": marker}).encode())
        except ClientError as exc:
            return exc, marker
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"expected the invoke to be rejected with reserved concurrency=0, but it "
                f"SUCCEEDED for {timeout_s}s and last returned {result!r}"
            )
        time.sleep(2.0)


def _reraise(exc):
    raise exc


def _invoke_once_unthrottled(lam, fn, payload, timeout_s=60.0):
    """Invoke, retrying only TooManyRequestsException while removing the reservation propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.invoke(FunctionName=fn, Payload=payload)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """At reserved concurrency 0, RequestResponse is refused with TooManyRequestsException "Rate
    Exceeded." (Reason ReservedFunctionConcurrentInvocationLimitExceeded); DryRun of the same
    function still answers 204, dispatching nothing; deleting the reservation restores success.
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    fn = _deploy_function(ctx, lam, _HANDLER)
    log_group = f"/aws/lambda/{fn}"

    # Positive control: the function actually runs before concurrency is touched at all, and
    # this measures how long a dispatched invoke takes to show up in its log group.
    control_marker = ctx.unique_name("control-")
    control_resp = lam.invoke(
        FunctionName=fn, Payload=json.dumps({"marker": control_marker}).encode()
    )
    assert control_resp["StatusCode"] == 200 and "FunctionError" not in control_resp, (
        f"positive control invoke did not succeed cleanly: "
        f"StatusCode={control_resp.get('StatusCode')!r}, "
        f"FunctionError={control_resp.get('FunctionError')!r}"
    )
    control_latency = _poll_marker(logs, log_group, control_marker, timeout_s=60)
    assert control_latency is not None, (
        f"positive control marker {control_marker!r} never appeared in {log_group} within 60s"
    )

    # Break: reserve zero concurrency for this function.
    lam.put_function_concurrency(FunctionName=fn, ReservedConcurrentExecutions=0)

    # A RequestResponse invoke is refused with the exact code, message and Reason.
    error, blocked_marker = _invoke_until_refused(lam, fn, lambda: ctx.unique_name("blocked-"))
    expect_error(lambda: _reraise(error), *_THROTTLE, reason=_THROTTLE_REASON)

    hold_s = max(3 * control_latency, 10.0)
    assert _held_absent(logs, log_group, blocked_marker, hold_s), (
        f"blocked invoke's marker {blocked_marker!r} appeared in {log_group} -- the function ran "
        f"despite the TooManyRequestsException"
    )

    # DryRun of the same function, under the same ReservedConcurrentExecutions=0, still answers
    # 204 with an empty body: the concurrency gate never sees it, because it never dispatches.
    dry_marker = ctx.unique_name("dryrun-")
    dry = lam.invoke(
        FunctionName=fn,
        InvocationType="DryRun",
        Payload=json.dumps({"marker": dry_marker}).encode(),
        LogType="Tail",
    )
    assert dry["StatusCode"] == 204, f"DryRun must return 204, got {dry['StatusCode']}"
    assert "FunctionError" not in dry, (
        f"DryRun reported FunctionError={dry.get('FunctionError')!r} -- the handler was "
        f"dispatched, which DryRun must never do"
    )
    assert dry["Payload"].read() == b"", "DryRun must return an empty response body"
    dry_log = base64.b64decode(dry.get("LogResult") or "").decode("utf-8", errors="replace")
    assert dry_marker not in dry_log, (
        f"DryRun must not dispatch the handler, but {dry_marker!r} was captured in its tailed "
        f"LogResult: {dry_log[:300]!r}"
    )
    assert _held_absent(logs, log_group, dry_marker, hold_s), (
        f"DryRun marker {dry_marker!r} appeared in {log_group} -- the handler ran despite "
        f"DryRun, with ReservedConcurrentExecutions=0 in effect"
    )

    # Restore: remove the reservation and demand an identical call now succeeds and actually
    # runs again.
    lam.delete_function_concurrency(FunctionName=fn)
    restored_marker = ctx.unique_name("restored-")
    resp2 = _invoke_once_unthrottled(lam, fn, json.dumps({"marker": restored_marker}).encode())
    assert resp2["StatusCode"] == 200 and "FunctionError" not in resp2, (
        f"identical invoke after restoring concurrency did not succeed: "
        f"StatusCode={resp2.get('StatusCode')!r}, FunctionError={resp2.get('FunctionError')!r}"
    )
    restored_latency = _poll_marker(logs, log_group, restored_marker, timeout_s=150)
    assert restored_latency is not None, (
        f"restored marker {restored_marker!r} never appeared in {log_group} within 150s -- the "
        f"identical call did not actually run after concurrency was restored"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
