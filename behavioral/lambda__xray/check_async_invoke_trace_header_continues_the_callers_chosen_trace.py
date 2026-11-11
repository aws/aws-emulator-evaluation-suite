"""async-invoke-trace-header-continues-the-callers-chosen-trace."""

from __future__ import annotations

import io
import json
import os
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "async-invoke-trace-header-continues-the-callers-chosen-trace"
GROUP = "distributed-tracing"
SERVICES = ["lambda", "xray"]

HANDLER = "exports.handler = async () => ({ ok: true });\n"

_ROLE_PROPAGATION = "cannot be assumed by Lambda"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An X-Amzn-Trace-Id header on an asynchronous Invoke of a TracingConfig Active function is
    the trace id its invocation is recorded under, not one X-Ray makes up on delivery: two async
    invocations with two distinct, caller-chosen trace ids are each filed under their own.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html
    Reference: https://docs.aws.amazon.com/xray/latest/devguide/xray-concepts.html#xray-concepts-tracingheader
    """
    lam = ctx.client("lambda")
    xray = ctx.client("xray")
    role_arn = _make_role(ctx, ctx.client("iam"))

    fn = _create_function(
        ctx, lam,
        FunctionName=ctx.unique_name("sim2real-behav-asyncinv-"),
        Runtime="nodejs22.x", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _zip("index.js", HANDLER)}, MemorySize=128, Timeout=15,
        TracingConfig={"Mode": "Active"}, Tags={"sim2real": CHECK},
    )

    for label in ("a", "b"):
        root, header = _trace_header()
        _invoke_async_with_header(lam, fn, header)
        traces = _poll_until(
            ctx,
            lambda r=root: xray.batch_get_traces(TraceIds=[r])["Traces"],
            lambda traces: bool(traces) and len(traces[0]["Segments"]) >= 2,
            timeout_s=120.0, interval_s=2.0,
            description=(
                f"async invocation {label!r} of {fn!r} to be recorded under its own trace "
                f"{root!r} (from header {header!r}) with both of its segments"
            ),
        )
        assert len(traces) == 1 and traces[0]["Id"] == root, (
            f"BatchGetTraces([{root!r}]) returned {[t['Id'] for t in traces]!r}"
        )
        segs = [json.loads(s["Document"]) for s in traces[0]["Segments"]]
        by_origin = {d.get("origin") for d in segs}
        assert by_origin == {"AWS::Lambda", "AWS::Lambda::Function"}, (
            f"trace {root!r} carries segment origins {by_origin!r}, expected the Lambda service "
            "node and the function node"
        )
        assert all(d.get("name") == fn for d in segs), (
            f"trace {root!r}'s segments name {[d.get('name') for d in segs]!r}, expected {fn!r}"
        )


# ===== helpers =====


def _trace_header() -> tuple[str, str]:
    """A fresh ``(root_id, "Root=...;Parent=...;Sampled=1")`` an instrumented caller might send.

    The trace id's first field is the current epoch time in hex, per X-Ray's trace id format; only
    the 24 hex-char unique id is random.
    """
    epoch = format(int(time.time()), "x")
    root = f"1-{epoch}-{os.urandom(12).hex()}"
    parent = os.urandom(8).hex()
    return root, f"Root={root};Parent={parent};Sampled=1"


def _invoke_async_with_header(lam, fn: str, header: str) -> None:
    """An asynchronous Invoke carrying ``header`` as its X-Amzn-Trace-Id, the way an
    X-Ray-instrumented upstream caller's SDK would sign the request."""

    def add_header(request, **kwargs):
        request.headers["X-Amzn-Trace-Id"] = header

    lam.meta.events.register_first("before-sign.lambda.Invoke", add_header)
    try:
        resp = lam.invoke(FunctionName=fn, InvocationType="Event", Payload=b"{}")
    finally:
        lam.meta.events.unregister("before-sign.lambda.Invoke", add_header)
    assert resp["StatusCode"] == 202, f"async Invoke({fn}) StatusCode {resp['StatusCode']!r}"


def _zip(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry on an observable condition. RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _make_role(ctx, iam) -> str:
    """This check's own execution role: logs + xray:PutTraceSegments, tagged with its scenario id."""
    name = ctx.unique_name("sim2real-behav-asyncinv-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    partition = role["Role"]["Arn"].split(":")[1]
    statements = [
        {"Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": f"arn:{partition}:logs:*:*:*"},
        {"Effect": "Allow",
         "Action": ["xray:PutTraceSegments", "xray:PutTelemetryRecords"], "Resource": "*"},
    ]
    iam.put_role_policy(
        RoleName=name, PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"), "NoSuchEntity",
    ))
    # IAM propagation exposes no pollable condition; the bounded role-propagation retry in
    # _create_function is what makes first use correct, so no fixed sleep is added here.
    return role["Role"]["Arn"]


def _group_exists(logs, group: str) -> bool:
    kw: dict = {"logGroupNamePrefix": group}
    while True:
        page = logs.describe_log_groups(**kw)
        if any(g["logGroupName"] == group for g in page.get("logGroups", [])):
            return True
        if not page.get("nextToken"):
            return False
        kw["nextToken"] = page["nextToken"]


def _reap_log_group(logs, group: str) -> None:
    """delete_function does not remove the function's log group, and a buffered flush can RECREATE
    it after the delete — so reap in a loop until it has stayed absent for three consecutive reads."""
    quiet = 0
    for _ in range(12):
        if _group_exists(logs, group):
            quiet = 0
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            quiet += 1
            if quiet >= 3:
                return
        time.sleep(3)
    if _group_exists(logs, group):
        raise RuntimeError(f"log group {group} kept reappearing after delete")


def _create_function(ctx, lam, **kwargs) -> str:
    """CreateFunction retrying ONLY the documented role-propagation refusal; waits for Active."""
    name = kwargs["FunctionName"]
    logs = ctx.client("logs")
    # Registered BEFORE the function exists, so LIFO runs it AFTER delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "")
            code = exc.response["Error"]["Code"]
            if code != "InvalidParameterValueException" or _ROLE_PROPAGATION not in msg:
                raise
            if time.monotonic() > deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(
                        "role propagation: the run budget ended first; not graded") from exc
                raise AssertionError(f"CreateFunction({name}) kept failing on role propagation: {msg}")
            time.sleep(2)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    _wait_ready(ctx, lam, name)
    return name


def _wait_ready(ctx, lam, name: str) -> dict:
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed":
            raise AssertionError(f"{name} failed: {cfg.get('StateReason')}")
        return cfg

    return _poll_until(
        ctx, _probe,
        lambda cfg: cfg.get("State") == "Active"
        and cfg.get("LastUpdateStatus") in (None, "Successful"),
        timeout_s=180.0, interval_s=2.0, description=f"{name} Active + LastUpdateStatus=Successful",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
