"""tracing-config-active-produces-a-trace-passthrough-produces-none."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tracing-config-active-produces-a-trace-passthrough-produces-none"
GROUP = "distributed-tracing"
SERVICES = ["lambda", "xray"]

HANDLER = """\
def handler(event:, context:)
  { ok: true }
end
"""


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A direct Invoke with no incoming trace header makes Lambda sample a trace under
    TracingConfig Mode=Active, queryable by GetTraceSummaries/BatchGetTraces, and none at all
    under the default Mode=PassThrough — same handler, same role, only the mode differs.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html
    Reference: https://docs.aws.amazon.com/xray/latest/api/API_GetTraceSummaries.html
    """
    lam = ctx.client("lambda")
    xray = ctx.client("xray")
    role_arn = _make_role(ctx, ctx.client("iam"))

    active_fn = _create_function(
        ctx, lam,
        FunctionName=ctx.unique_name("sim2real-behav-trc-act-"),
        Runtime="ruby3.4", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _zip("index.rb", HANDLER)}, MemorySize=128, Timeout=15,
        TracingConfig={"Mode": "Active"}, Tags={"sim2real": CHECK},
    )
    passthrough_fn = _create_function(
        ctx, lam,
        FunctionName=ctx.unique_name("sim2real-behav-trc-pt-"),
        Runtime="ruby3.4", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _zip("index.rb", HANDLER)}, MemorySize=128, Timeout=15,
        TracingConfig={"Mode": "PassThrough"}, Tags={"sim2real": CHECK},
    )

    active_cfg = lam.get_function_configuration(FunctionName=active_fn)
    assert active_cfg["TracingConfig"]["Mode"] == "Active", active_cfg["TracingConfig"]
    pt_cfg = lam.get_function_configuration(FunctionName=passthrough_fn)
    assert pt_cfg["TracingConfig"]["Mode"] == "PassThrough", pt_cfg["TracingConfig"]

    started = time.time()
    _invoke(lam, passthrough_fn)
    _invoke(lam, active_fn)

    def _fn_segments():
        ids = _summary_ids(xray, started - 5, active_fn)
        if not ids:
            return None, []
        traces = xray.batch_get_traces(TraceIds=sorted(ids))["Traces"]
        segs = [json.loads(s["Document"]) for t in traces for s in t["Segments"]]
        return ids, [d for d in segs if d.get("origin") == "AWS::Lambda::Function" and d.get("end_time")]

    active_ids, fn_segs = _poll_until(
        _fn_segments,
        lambda r: bool(r[1]),
        timeout_s=120.0, interval_s=5.0,
        description=f"a completed AWS::Lambda::Function segment for {active_fn!r} (Mode=Active)",
    )
    assert len(active_ids) == 1, (
        f"expected exactly one trace for the Active invocation of {active_fn!r}, got {active_ids!r}"
    )
    (trace_id,) = active_ids
    traces = xray.batch_get_traces(TraceIds=[trace_id])["Traces"]
    assert [t["Id"] for t in traces] == [trace_id], (
        f"BatchGetTraces([{trace_id!r}]) returned {[t['Id'] for t in traces]!r}"
    )
    assert len(fn_segs) == 1, (
        f"expected exactly one AWS::Lambda::Function segment for {active_fn!r}, got "
        f"{[d.get('id') for d in fn_segs]!r}"
    )
    assert fn_segs[0].get("name") == active_fn, (
        f"the AWS::Lambda::Function segment names {fn_segs[0].get('name')!r}, expected {active_fn!r}"
    )

    # PassThrough was invoked BEFORE Active, over the same window just proven (above) long enough
    # for X-Ray to deliver and close a trace. A single read after that positive control rules out
    # "merely not delivered yet" without a fixed observation window of its own.
    pt_ids = _summary_ids(xray, started - 5, passthrough_fn)
    assert pt_ids == set(), (
        f"TracingConfig Mode=PassThrough with no incoming trace header must not sample a trace, "
        f"but GetTraceSummaries returned {pt_ids!r} for {passthrough_fn!r}"
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


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry on an observable condition. RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _make_role(ctx, iam) -> str:
    """This check's own execution role: logs + xray:PutTraceSegments, tagged with its scenario id."""
    name = ctx.unique_name("sim2real-behav-trc-")
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
    deadline = time.monotonic() + 90.0
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
                raise AssertionError(f"CreateFunction({name}) kept failing on role propagation: {msg}")
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    _wait_ready(lam, name)
    return name


def _wait_ready(lam, name: str) -> dict:
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed":
            raise AssertionError(f"{name} failed: {cfg.get('StateReason')}")
        return cfg

    return _poll_until(
        _probe,
        lambda cfg: cfg.get("State") == "Active"
        and cfg.get("LastUpdateStatus") in (None, "Successful"),
        timeout_s=180.0, interval_s=2.0, description=f"{name} Active + LastUpdateStatus=Successful",
    )


def _invoke(lam, fn: str) -> None:
    """Synchronous invoke, retrying while the role is still propagating."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            resp = lam.invoke(FunctionName=fn, Payload=b"{}")
            break
        except ClientError as exc:
            if "cannot be assumed" not in str(exc) or time.monotonic() > deadline:
                raise
            time.sleep(3)
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
