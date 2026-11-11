"""metrics-math-and-emf-lambda-stdout-emf-line-materializes-metric-without-put-metric-data."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-math-and-emf-lambda-stdout-emf-line-materializes-metric-without-put-metric-data"
GROUP = "embedded-metric-format"
SERVICES = ["cloudwatch", "lambda", "logs"]

# The handler only PRINTS. It never imports boto3 and never calls PutMetricData.
_HANDLER = """
def handler(event, context):
    for line in event["lines"]:
        print(line, flush=True)
    return {"printed": len(event["lines"])}
"""

_TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"}]})
# The role cannot publish a metric, so a datapoint can only come from EMF extraction.
_DENY_PUT_METRIC_DATA = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Deny", "Action": "cloudwatch:PutMetricData", "Resource": "*"}]})


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """An EMF line printed by a Lambda that cannot call PutMetricData yields the declared metric with
    exact unit, dimension set and aggregates (Sum 90, n 3, 12..48); unit/dimension mismatches find
    nothing, and the raw line is stored verbatim in the function's log group.
    """
    cw = ctx.client("cloudwatch")
    logs = ctx.client("logs")
    namespace = ctx.unique_name("sim2real-mme-emf/")
    fn = ctx.unique_name("sim2real-mme-emf-fn-")
    group = f"/aws/lambda/{fn}"

    # The log group is reaped in a loop registered BEFORE the function exists, so LIFO runs it
    # after the function is gone and a late flush that recreates the group is caught.
    ctx.on_cleanup(lambda: _reap_log_group(logs, group))
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    logs.put_retention_policy(logGroupName=group, retentionInDays=1)

    role_arn = _create_role(ctx, {"deny-put-metric-data": _DENY_PUT_METRIC_DATA})
    _create_function(ctx, fn, role_arn)

    now_ms = int(time.time() * 1000)
    line = json.dumps({
        "_aws": {"Timestamp": now_ms, "CloudWatchMetrics": [{
            "Namespace": namespace, "Dimensions": [["Service", "Stage"]],
            "Metrics": [{"Name": "CheckoutLatency", "Unit": "Milliseconds"}]}]},
        "Service": "checkout", "Stage": "prod", "CheckoutLatency": [12, 30, 48],
        "requestId": "req-0001",
    }, separators=(",", ":"))
    _invoke(ctx, fn, [line])

    dims = [{"Name": "Service", "Value": "checkout"}, {"Name": "Stage", "Value": "prod"}]
    start = datetime.fromtimestamp(now_ms / 1000, timezone.utc) - timedelta(minutes=5)
    end = datetime.now(timezone.utc) + timedelta(minutes=5)

    def stats(d, unit=None):
        kw = dict(Namespace=namespace, MetricName="CheckoutLatency", Dimensions=d,
                  StartTime=start, EndTime=end, Period=60,
                  Statistics=["Sum", "SampleCount", "Minimum", "Maximum"])
        if unit:
            kw["Unit"] = unit
        return cw.get_metric_statistics(**kw)["Datapoints"]

    dps = _poll(lambda: stats(dims), lambda d: sum(p["SampleCount"] for p in d) >= 3,
                "the EMF-declared metric to materialise with all three values")
    assert len(dps) == 1, f"expected the three values in one 60 s bucket, got {dps!r}"
    dp = dps[0]
    got = (dp["Sum"], dp["SampleCount"], dp["Minimum"], dp["Maximum"], dp["Unit"])
    assert got == (90.0, 3.0, 12.0, 48.0, "Milliseconds"), (
        f"extracted metric (Sum, SampleCount, Min, Max, Unit) was {got!r}; "
        "expected (90.0, 3.0, 12.0, 48.0, 'Milliseconds')"
    )
    with_unit = stats(dims, unit="Milliseconds")
    assert [p["Sum"] for p in with_unit] == [90.0], f"Unit=Milliseconds query returned {with_unit!r}"

    # Effect absent: identity is namespace + name + EXACT dimension set + unit.
    wrong_unit = stats(dims, unit="Seconds")
    assert wrong_unit == [], f"Unit=Seconds query returned {wrong_unit!r}; the declared unit is ms"
    subset = stats([{"Name": "Service", "Value": "checkout"}])
    assert subset == [], f"a {{Service}}-only query returned {subset!r}; not a declared dimension set"
    superset = stats(dims + [{"Name": "requestId", "Value": "req-0001"}])
    assert superset == [], f"requestId became a dimension: {superset!r}"

    events = _poll(lambda: _log_messages(logs, group, now_ms), lambda m: line in m,
                   f"the EMF line stored in {group}")
    assert line in events, f"the EMF line is not in {group} verbatim; messages were {events!r}"


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
    deadline = time.monotonic() + 60.0
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + left)
    while True:
        try:
            lam.create_function(FunctionName=name, Runtime="python3.12", Role=role_arn,
                                Handler="lambda_function.handler", Code={"ZipFile": _zip(_HANDLER)},
                                Timeout=15, MemorySize=128, Tags={"sim2real": CHECK})
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            # IAM role propagation exposes no pollable condition; retry the first use.
            if time.monotonic() >= deadline:
                raise AssertionError(f"create_function never accepted the new role: {exc!r}") from exc
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


def _log_messages(logs, group: str, since_ms: int) -> list[str]:
    msgs: list[str] = []
    kw = dict(logGroupName=group, startTime=since_ms - 60_000)
    while True:
        resp = logs.filter_log_events(**kw)
        msgs.extend(e["message"].rstrip("\n") for e in resp["events"])
        if not resp.get("nextToken"):
            return msgs
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


def _poll(fn, ready, what: str, timeout_s=220, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if ready(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"never observed {what}; last read {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
