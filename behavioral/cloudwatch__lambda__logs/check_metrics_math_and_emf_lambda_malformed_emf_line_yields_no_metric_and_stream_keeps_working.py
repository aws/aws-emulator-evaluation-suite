"""metrics-math-and-emf-lambda-malformed-emf-line-yields-no-metric-and-stream-keeps-working."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-math-and-emf-lambda-malformed-emf-line-yields-no-metric-and-stream-keeps-working"
GROUP = "embedded-metric-format"
SERVICES = ["cloudwatch", "lambda", "logs"]

_HANDLER = """
def handler(event, context):
    for line in event["lines"]:
        print(line, flush=True)
    return {"printed": len(event["lines"])}
"""

_TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"}]})
_DENY_PUT_METRIC_DATA = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Deny", "Action": "cloudwatch:PutMetricData", "Resource": "*"}]})

_BROKEN_VALUE = 1000.0
_HOLD_S = 10.0  # absence must hold over this window after the barrier, not just at it


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _emf(namespace: str, ts_ms: int, name: str, value: float, dimensions) -> str:
    return json.dumps({
        "_aws": {"Timestamp": ts_ms, "CloudWatchMetrics": [{
            "Namespace": namespace, "Dimensions": dimensions,
            "Metrics": [{"Name": name, "Unit": "Count"}]}]},
        "Service": "checkout", name: value,
    }, separators=(",", ":"))


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """Truncated and flat-Dimensions EMF lines from Lambda publish nothing (repaired lines alone give
    Sum 4 and 3), a later control line is still extracted, and all lines are stored in one stream.
    """
    cw = ctx.client("cloudwatch")
    logs = ctx.client("logs")
    namespace = ctx.unique_name("sim2real-mme-emfbad/")
    fn = ctx.unique_name("sim2real-mme-emfbad-fn-")
    group = f"/aws/lambda/{fn}"

    ctx.on_cleanup(lambda: _reap_log_group(logs, group))
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    logs.put_retention_policy(logGroupName=group, retentionInDays=1)
    # The role denies PutMetricData, so any datapoint can only come from EMF extraction.
    role_arn = _create_role(ctx, {"deny-put-metric-data": _DENY_PUT_METRIC_DATA})
    _create_function(ctx, fn, role_arn)

    t1 = int(time.time() * 1000)
    truncated = _emf(namespace, t1, "Truncated", _BROKEN_VALUE, [["Service"]])[:-1]
    flat = _emf(namespace, t1, "FlatDims", _BROKEN_VALUE, ["Service"])
    good1 = _emf(namespace, t1, "Good", 5.0, [["Service"]])
    assert not _parses(truncated) and _parses(flat), "test-data invariant: exactly one line is not JSON"
    _invoke(ctx, fn, [truncated, flat, good1])

    # Repaired lines under the same names prove each broken metric's slot is reachable.
    t2 = int(time.time() * 1000)
    _invoke(ctx, fn, [
        _emf(namespace, t2, "Good", 7.0, [["Service"]]),
        _emf(namespace, t2, "Truncated", 4.0, [["Service"]]),
        _emf(namespace, t2, "FlatDims", 3.0, [["Service"]]),
    ])

    start = datetime.fromtimestamp(t1 / 1000, timezone.utc) - timedelta(minutes=5)
    end = datetime.now(timezone.utc) + timedelta(minutes=5)

    def agg(name):
        dps = cw.get_metric_statistics(
            Namespace=namespace, MetricName=name,
            Dimensions=[{"Name": "Service", "Value": "checkout"}],
            StartTime=start, EndTime=end, Period=60, Statistics=["Sum", "SampleCount"],
        )["Datapoints"]
        return (sum(d["Sum"] for d in dps), sum(d["SampleCount"] for d in dps))

    def snapshot():
        return {n: agg(n) for n in ("Good", "Truncated", "FlatDims")}

    snap = _poll(snapshot, lambda s: s["Good"] == (12.0, 2.0) and s["Truncated"][1] >= 1
                 and s["FlatDims"][1] >= 1,
                 "the control metric from both invocations and both repaired metrics",
                 timeout_s=_budget_s(ctx, 200), ctx=ctx)
    # Re-read every 2 s across the hold.
    hold_end = time.monotonic() + _HOLD_S
    while True:
        assert snap["Good"] == (12.0, 2.0), f"control Good was {snap['Good']!r}, expected (12.0, 2.0)"
        assert snap["Truncated"] == (4.0, 1.0), (
            f"Truncated (Sum, SampleCount) was {snap['Truncated']!r}: the truncated EMF line "
            f"contributed a datapoint; expected only the repaired value (4.0, 1.0)"
        )
        assert snap["FlatDims"] == (3.0, 1.0), (
            f"FlatDims (Sum, SampleCount) was {snap['FlatDims']!r}: the flat-Dimensions EMF line "
            f"contributed a datapoint; expected only the repaired value (3.0, 1.0)"
        )
        if time.monotonic() >= hold_end:
            break
        time.sleep(2)
        snap = snapshot()

    # Delivery undamaged: all three invocation-1 lines stored verbatim, in order, one stream.
    first = [truncated, flat, good1]
    events = _poll(lambda: _log_events(logs, group, t1),
                   lambda ev: all(any(m == line for _, m in ev) for line in first),
                   f"all invocation-1 lines stored in {group}", timeout_s=_budget_s(ctx, 200),
                   ctx=ctx)
    picked = [(s, m) for s, m in events if m in first]
    assert [m for _, m in picked] == first, (
        f"invocation-1 lines stored as {[m[:40] for _, m in picked]!r}; expected all three in order"
    )
    assert len({s for s, _ in picked}) == 1, f"invocation-1 lines split across streams {picked!r}"


def _parses(line: str) -> bool:
    try:
        json.loads(line)
    except ValueError:
        return False
    return True


def _zip(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", source)
    return buf.getvalue()


def _create_role(ctx, inline: dict[str, str]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-mme-role-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_TRUST,
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.attach_role_policy(RoleName=name, PolicyArn=(
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"))
    for pname, doc in inline.items():
        iam.put_role_policy(RoleName=name, PolicyName=pname, PolicyDocument=doc)
    return arn


def _delete_role(iam, name: str) -> None:
    for pol in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
        iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
    for pname in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=pname)
    iam.delete_role(RoleName=name)


def _create_function(ctx, name: str, role_arn: str) -> None:
    lam = ctx.client("lambda")
    last = None
    deadline = time.monotonic() + _budget_s(ctx, 60)
    while True:
        try:
            lam.create_function(FunctionName=name, Runtime="python3.12", Role=role_arn,
                                Handler="lambda_function.handler", Code={"ZipFile": _zip(_HANDLER)},
                                Timeout=15, MemorySize=128, Tags={"sim2real": CHECK})
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            # IAM role propagation exposes no pollable condition; retry the first use.
            last = exc
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError("create_function accepting the new role: the run budget ended "
                                       "first; not graded") from exc
                raise AssertionError(f"create_function never accepted the new role: {last!r}")
            time.sleep(2)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name,
                                              WaiterConfig={"Delay": 2, "MaxAttempts": 60})


def _invoke(ctx, name: str, lines: list[str]) -> None:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=name, InvocationType="RequestResponse",
                      Payload=json.dumps({"lines": lines}).encode())
    body = json.loads(resp["Payload"].read())
    assert resp["StatusCode"] == 200 and "FunctionError" not in resp, f"invoke failed: {body!r}"
    assert body == {"printed": len(lines)}, f"handler returned {body!r}"


def _log_events(logs, group: str, since_ms: int) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    kw = dict(logGroupName=group, startTime=since_ms - 60_000)
    while True:
        resp = logs.filter_log_events(**kw)
        out.extend((e["logStreamName"], e["message"].rstrip("\n")) for e in resp["events"])
        if not resp.get("nextToken"):
            return out
        kw["nextToken"] = resp["nextToken"]


def _reap_log_group(logs, group: str) -> None:
    for _ in range(6):
        try:
            logs.delete_log_group(logGroupName=group)
        except logs.exceptions.ResourceNotFoundException:
            pass
        time.sleep(5)
        found = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        if not any(g["logGroupName"] == group for g in found):
            return
    raise RuntimeError(f"log group {group} kept reappearing after delete")


def _poll(fn, ready, what: str, timeout_s=200, interval_s=2.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if ready(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{what}: the run budget ended first; not graded")
    raise AssertionError(f"never observed {what}; last read {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
