"""reserved-zero-blocks-invoke."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "reserved-zero-blocks-invoke"
GROUP = 'concurrency'
SERVICES = ['lambda']


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLES: dict = {}
_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _role_arn(ctx):
    """An execution role this check creates once per run and deletes in its teardown."""
    import json as _json

    held = _ROLES.get(id(ctx))
    if held is not None and held[0] is ctx:
        return held[1]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY))
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
        ("DeleteFunctionUrlConfig", lambda: lam.delete_function_url_config(FunctionName=name)),
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
        except Exception as exc:  # noqa: BLE001 - collected and raised below
            failed.append(f"{label}: {exc!r}")
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


def _deploy_function(ctx, lam, code, *, name=None, handler="index.handler",
                     runtime="python3.12", memory=128, timeout=30, environment=None,
                     layers=None, ephemeral_storage=None, role=None):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    kwargs = {
        "FunctionName": name,
        "Runtime": runtime,
        "Handler": handler,
        "Role": role or _role_arn(ctx),
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
    _create_function(lam, **kwargs)
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _invoke_until_refused(lam, fn, marker_fn, timeout_s=60.0):
    """Invoke until the call is refused; return (error, marker of the refused call).

    PutFunctionConcurrency(0) is applied with a short propagation lag on real AWS, so an invoke
    issued right after it can still run. A call that keeps succeeding past *timeout_s* raises as
    an unexpected success."""
    deadline = time.monotonic() + timeout_s
    while True:
        marker = marker_fn()
        try:
            result = lam.invoke(FunctionName=fn, Payload=json.dumps({"marker": marker}).encode())
        except ClientError as exc:
            return exc.response.get("Error", {}), marker
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"expected the invoke to be rejected with reserved concurrency=0, but it "
                f"SUCCEEDED for {timeout_s}s and last returned {result!r}"
            )
        time.sleep(2.0)


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


def _marker_present(logs, log_group, marker):
    """Whether any event in the group carries ``marker``, over every FilterLogEvents page: a
    page may come back empty with a nextToken while later streams still hold matches."""
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
    deadline = time.monotonic() + timeout_s
    start = time.monotonic()
    while time.monotonic() < deadline:
        if _marker_present(logs, log_group, marker):
            return time.monotonic() - start
        time.sleep(1.0)
    return None


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Reserved concurrency = 0 blocks invocation with TooManyRequestsException, the block is
    real -- the function body never executes, not merely mislabelled -- and restoring
    unreserved concurrency lets an identical invoke through again."""
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    fn = _deploy_function(
        ctx, lam, 'def handler(event, context):\n    print("MARKER:" + event.get("marker", ""))\n    return event\n'
    )
    log_group = f"/aws/lambda/{fn}"

    # Positive control: the function actually runs before concurrency is touched at all.
    control_marker = ctx.unique_name("control-")
    resp = lam.invoke(FunctionName=fn, Payload=json.dumps({"marker": control_marker}).encode())
    assert resp["StatusCode"] == 200 and "FunctionError" not in resp, (
        f"positive control invoke did not succeed cleanly: StatusCode={resp.get('StatusCode')!r}, "
        f"FunctionError={resp.get('FunctionError')!r}"
    )
    control_latency = _poll_marker(logs, log_group, control_marker, timeout_s=60)
    assert control_latency is not None, (
        f"positive control marker {control_marker!r} never appeared in {log_group} within 60s"
    )

    # Break: reserve zero concurrency for this function.
    lam.put_function_concurrency(FunctionName=fn, ReservedConcurrentExecutions=0)

    # Assert the specific refusal.
    error, blocked_marker = _invoke_until_refused(lam, fn, lambda: ctx.unique_name("blocked-"))
    assert error.get("Code") == "TooManyRequestsException", (
        f"invoke with ReservedConcurrentExecutions=0 was rejected with {error.get('Code')!r}, "
        f"expected 'TooManyRequestsException'"
    )
    assert error.get("Message") == "Rate Exceeded.", (
        f'expected the exact TooManyRequestsException message AWS returns, got {error.get("Message")!r}'
    )

    # Assert the effect is absent via an independent read: the function body must never have
    # run, so its marker must never appear -- held for >= 3x the positive control's own
    # end-to-end log-delivery latency, never a bare sleep.
    hold_s = max(3 * control_latency, 10.0)
    deadline = time.monotonic() + hold_s
    while time.monotonic() < deadline:
        assert not _marker_present(logs, log_group, blocked_marker), (
            f"blocked invoke's marker {blocked_marker!r} appeared in {log_group} -- the "
            f"function ran despite the TooManyRequestsException"
        )
        time.sleep(1.0)

    # Restore: remove the reservation and demand the identical call now succeeds.
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
