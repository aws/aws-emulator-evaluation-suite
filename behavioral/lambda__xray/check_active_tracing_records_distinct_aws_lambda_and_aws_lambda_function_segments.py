"""active-tracing-records-distinct-aws-lambda-and-aws-lambda-function-segments."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "active-tracing-records-distinct-aws-lambda-and-aws-lambda-function-segments"
GROUP = "distributed-tracing"
SERVICES = ["lambda", "xray"]

HANDLER = "exports.handler = async () => ({ ok: true });\n"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A sampled trace under TracingConfig Mode=Active records exactly two segments for one
    invocation: an AWS::Lambda segment (the service's own preparation of the invocation) and an
    AWS::Lambda::Function segment (the function's own execution), both named after the function.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html
    Reference: https://docs.aws.amazon.com/xray/latest/api/API_BatchGetTraces.html
    """
    lam = ctx.client("lambda")
    xray = ctx.client("xray")
    role_arn = _make_role(ctx, ctx.client("iam"))

    fn = _create_function(
        ctx, lam,
        FunctionName=ctx.unique_name("sim2real-behav-segshape-"),
        Runtime="nodejs22.x", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _zip("index.js", HANDLER)}, MemorySize=128, Timeout=15,
        TracingConfig={"Mode": "Active"}, Tags={"sim2real": CHECK},
    )

    started = time.time()
    _invoke(ctx, lam, fn)

    def _trace_for_fn():
        ids = _summary_ids(xray, started - 5, fn)
        if not ids:
            return None, []
        traces = xray.batch_get_traces(TraceIds=sorted(ids))["Traces"]
        segs = [json.loads(s["Document"]) for t in traces for s in t["Segments"]]
        return ids, segs

    ids, segs = _poll_until(
        ctx, _trace_for_fn,
        lambda r: {d.get("origin") for d in r[1]} >= {"AWS::Lambda", "AWS::Lambda::Function"},
        timeout_s=_budget_s(ctx, 120.0),
        description=f"a trace carrying both an AWS::Lambda and an AWS::Lambda::Function segment "
                    f"for {fn!r}",
    )
    assert len(ids) == 1, f"expected exactly one trace for {fn!r}'s invocation, got {ids!r}"

    by_origin: dict[str, list[dict]] = {}
    for doc in segs:
        by_origin.setdefault(doc.get("origin"), []).append(doc)

    fn_segs = by_origin.get("AWS::Lambda::Function", [])
    assert len(fn_segs) == 1, (
        f"expected exactly one AWS::Lambda::Function segment for {fn!r}, got "
        f"{[d.get('id') for d in fn_segs]!r}"
    )
    assert fn_segs[0].get("name") == fn, (
        f"the AWS::Lambda::Function segment names {fn_segs[0].get('name')!r}, expected {fn!r}"
    )

    svc_segs = by_origin.get("AWS::Lambda", [])
    assert len(svc_segs) == 1, (
        f"expected exactly one AWS::Lambda segment (the service's own node) for {fn!r}'s trace, "
        f"got {[d.get('id') for d in svc_segs]!r}; origins present were {sorted(by_origin)!r}"
    )
    assert svc_segs[0].get("name") == fn, (
        f"the AWS::Lambda segment names {svc_segs[0].get('name')!r}, expected {fn!r}"
    )
    assert svc_segs[0]["id"] != fn_segs[0]["id"], (
        "the AWS::Lambda and AWS::Lambda::Function segments must be two distinct segment ids, "
        f"both reported {svc_segs[0]['id']!r}"
    )
    assert svc_segs[0]["trace_id"] == fn_segs[0]["trace_id"], (
        f"the two segments disagree on trace_id: {svc_segs[0]['trace_id']!r} vs "
        f"{fn_segs[0]['trace_id']!r}"
    )
    assert sorted(by_origin) == ["AWS::Lambda", "AWS::Lambda::Function"], (
        f"the trace carries segment origins {sorted(by_origin)!r}, expected exactly the Lambda "
        "service node and the function node"
    )


# ===== helpers =====

_ROLE_PROPAGATION = "cannot be assumed by Lambda"


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


def _poll_until(ctx, probe, predicate, *, timeout_s: float, interval_s: float = 2.0,
                description: str):
    """Bounded retry on an observable condition. RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _make_role(ctx, iam) -> str:
    """This check's own execution role: logs + xray:PutTraceSegments, tagged with its scenario id."""
    name = ctx.unique_name("sim2real-behav-segshape-")
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
                        f"CreateFunction({name}): the run budget ended first; not graded"
                    ) from exc
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
        timeout_s=_budget_s(ctx, 180.0),
        description=f"{name} Active + LastUpdateStatus=Successful",
    )


def _invoke(ctx, lam, fn: str) -> None:
    """Synchronous invoke, retrying while the role is still propagating."""
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    while True:
        try:
            resp = lam.invoke(FunctionName=fn, Payload=b"{}")
            break
        except ClientError as exc:
            if "cannot be assumed" not in str(exc):
                raise
            if time.monotonic() > deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(f"Invoke({fn}): the run budget ended first; not graded") from exc
                raise
            time.sleep(2)
    raw = resp["Payload"].read()
    assert resp["StatusCode"] == 200, f"Invoke({fn}) StatusCode {resp['StatusCode']!r}: {raw[:300]!r}"
    assert "FunctionError" not in resp, f"{fn} raised unexpectedly: {resp.get('FunctionError')!r}"


def _summary_ids(xray, start: float, function_name: str) -> set:
    """Every trace id GetTraceSummaries returns for ``function_name``'s own service node."""
    kwargs: dict = {
        "StartTime": start, "EndTime": time.time() + 5,
        "FilterExpression": f'service("{function_name}")',
    }
    ids: set = set()
    token = None
    while True:
        if token:
            kwargs["NextToken"] = token
        resp = xray.get_trace_summaries(**kwargs)
        ids.update(s["Id"] for s in resp.get("TraceSummaries") or [])
        token = resp.get("NextToken")
        if not token:
            return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
