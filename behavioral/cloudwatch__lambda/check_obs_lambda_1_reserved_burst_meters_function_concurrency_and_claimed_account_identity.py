"""obs-lambda-1-reserved-burst-meters-function-concurrency-and-claimed-account-identity."""
from __future__ import annotations

import io
import json
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "obs-lambda-1-reserved-burst-meters-function-concurrency-and-claimed-account-identity"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "lambda"]

_RESERVED = 6          # R on function A
_BURST_A = 4           # K: rendezvous invokes of A (K < R, so none is throttled)
_BURST_B = 3           # rendezvous invokes of the UNRESERVED function B, same wave
_PC = 1                # provisioned concurrency on an alias of function C, never invoked
_SLEEP_MS = 10000      # each burst invoke holds its slot this long once the wave has met
_RENDEZVOUS_S = 30
_MIN_UNRESERVED = 100  # Lambda's documented floor on what reservations must leave unreserved
_PC_READY_BUDGET_S = 420.0
_METRIC_BUDGET_S = 300.0
_ROLE_PROPAGATION_BUDGET_S = 120.0

_HANDLER = '''
import json
import time

import boto3
from botocore.exceptions import ClientError

_CW = boto3.client("cloudwatch")
_BODY = json.dumps({"widgets": [{"type": "text", "x": 0, "y": 0, "width": 6, "height": 3,
                                 "properties": {"markdown": "rendezvous"}}]})


def _registered(prefix):
    names, kw = set(), {"DashboardNamePrefix": prefix}
    while True:
        page = _CW.list_dashboards(**kw)
        names.update(d["DashboardName"] for d in page.get("DashboardEntries", []))
        if not page.get("NextToken"):
            return len(names)
        kw["NextToken"] = page["NextToken"]


def _rendezvous(event, context):
    # Register as a dashboard under the wave's prefix, then wait (bounded) until the whole wave
    # has registered: the wave's invocations are in flight at once by construction.
    prefix = event["rv_prefix"]
    _CW.put_dashboard(DashboardName=prefix + context.aws_request_id, DashboardBody=_BODY)
    deadline = time.time() + event["wait_s"]
    while time.time() < deadline:
        try:
            if _registered(prefix) >= event["n"]:
                return True
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in ("Throttling",
                                                                  "ThrottlingException"):
                raise
        time.sleep(1.0)
    return False


def handler(event, context):
    met = _rendezvous(event, context) if event.get("rv_prefix") else None
    t0 = time.time()
    time.sleep(event.get("sleep_ms", 0) / 1000.0)
    return {"start": t0, "end": time.time(), "met": met}
'''


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-types.html
@tags("cap:c3", "concern:metrics", "concern:data-plane", "dp:api", "plane:data", "axis:happy-path",
      "timing:real-time")
def run(ctx) -> None:
    """A reserved function's 4-way rendezvous burst meters ConcurrentExecutions == 4 with no
    Throttles, an unreserved 3-way burst in the same wave counts in UnreservedConcurrentExecutions,
    and ClaimedAccountConcurrency minus UnreservedConcurrentExecutions equals the allocation.
    """
    lam = ctx.client("lambda")
    cw = ctx.client("cloudwatch")

    settings = lam.get_account_settings()["AccountLimit"]
    room = settings["UnreservedConcurrentExecutions"] - _RESERVED - _PC
    assert room >= _MIN_UNRESERVED + _BURST_B, (
        f"account reports UnreservedConcurrentExecutions="
        f"{settings['UnreservedConcurrentExecutions']!r}; reserving {_RESERVED} and provisioning "
        f"{_PC} would leave {room}, below the {_MIN_UNRESERVED} floor plus the {_BURST_B}-way burst"
    )

    rv_prefix = ctx.unique_name("sim2real-olam-rv-")
    ctx.on_cleanup(lambda: _delete_dashboards(cw, rv_prefix))
    role_arn = _role(ctx, rv_prefix)
    fn_a = _function(ctx, lam, role_arn, "rsv")
    fn_b = _function(ctx, lam, role_arn, "unr")
    fn_c = _function(ctx, lam, role_arn, "pcc")

    lam.put_function_concurrency(FunctionName=fn_a, ReservedConcurrentExecutions=_RESERVED)
    ctx.on_cleanup(lambda: lam.delete_function_concurrency(FunctionName=fn_a))
    got = lam.get_function_concurrency(FunctionName=fn_a).get("ReservedConcurrentExecutions")
    assert got == _RESERVED, f"GetFunctionConcurrency on {fn_a} read {got!r}, set {_RESERVED}"

    v_c = lam.publish_version(FunctionName=fn_c)["Version"]
    lam.create_alias(FunctionName=fn_c, Name="warm", FunctionVersion=v_c)
    ctx.on_cleanup(lambda: lam.delete_alias(FunctionName=fn_c, Name="warm"))
    lam.put_provisioned_concurrency_config(
        FunctionName=fn_c, Qualifier="warm", ProvisionedConcurrentExecutions=_PC
    )
    ctx.on_cleanup(
        lambda: lam.delete_provisioned_concurrency_config(FunctionName=fn_c, Qualifier="warm")
    )
    cfg = _poll_until(
        lambda: lam.get_provisioned_concurrency_config(FunctionName=fn_c, Qualifier="warm"),
        lambda c: c["Status"] in ("READY", "FAILED"),
        timeout_s=_budget_s(ctx, _PC_READY_BUDGET_S),
        interval_s=10.0,
        description=f"provisioned concurrency on {fn_c}:warm leaving IN_PROGRESS",
    )
    assert cfg["Status"] == "READY", f"PC on {fn_c}:warm ended {cfg['Status']!r}: {cfg!r}"

    # Every allocation is in place from here on. The identity is only meaningful over minutes that
    # begin after this instant, so the burst waits for the next minute boundary.
    alloc_before = _allocated(lam)
    in_place = datetime.now(timezone.utc)
    clean_from = _minute_floor(in_place) + timedelta(minutes=1)
    _poll_until(
        lambda: datetime.now(timezone.utc),
        lambda now: now >= clean_from + timedelta(seconds=2),
        timeout_s=_budget_s(ctx, 75.0),
        interval_s=2.0,
        description="the wall clock entering the first minute wholly after the allocations",
    )

    event = {"rv_prefix": rv_prefix, "n": _BURST_A + _BURST_B, "wait_s": _RENDEZVOUS_S,
             "sleep_ms": _SLEEP_MS}

    def _one(target: str):
        r = lam.invoke(FunctionName=target, Payload=json.dumps(event).encode())
        raw = r["Payload"].read()
        assert r["StatusCode"] == 200 and r.get("FunctionError") is None, (
            f"invoke {target} returned {r['StatusCode']!r} {r.get('FunctionError')!r} {raw!r}"
        )
        return target, json.loads(raw)

    with ThreadPoolExecutor(max_workers=_BURST_A + _BURST_B) as pool:
        results = list(pool.map(_one, [fn_a] * _BURST_A + [fn_b] * _BURST_B))
    unmet = [(t, b) for t, b in results if b.get("met") is not True]
    assert not unmet, (
        f"{len(unmet)} of {_BURST_A + _BURST_B} burst invokes never saw the whole wave registered "
        f"within {_RENDEZVOUS_S}s (the target must run them concurrently): {unmet!r}"
    )
    ivs_a = [(b["start"], b["end"]) for t, b in results if t == fn_a]
    ivs_b = [(b["start"], b["end"]) for t, b in results if t == fn_b]
    burst_minutes = {
        _minute_floor(datetime.fromtimestamp(t, timezone.utc)) for iv in ivs_a + ivs_b for t in iv
    }

    a_dims = [("FunctionName", fn_a)]
    queries = {
        "aconc": ("ConcurrentExecutions", a_dims, "Maximum"),
        "ainv": ("Invocations", a_dims, "Sum"),
        "athr": ("Throttles", a_dims, "Sum"),
        "unres": ("UnreservedConcurrentExecutions", [], "Maximum"),
        "claim": ("ClaimedAccountConcurrency", [], "Maximum"),
    }

    def _ready(got) -> bool:
        a_ok = max(got["aconc"].values(), default=0) >= _BURST_A and sum(
            got["ainv"].values()
        ) >= _BURST_A
        both = [t for t in burst_minutes if t in got["unres"] and t in got["claim"]]
        return a_ok and len(both) == len(burst_minutes)

    seen = _poll_until(
        lambda: _read(cw, queries, clean_from - timedelta(minutes=1)),
        _ready,
        timeout_s=_budget_s(ctx, _METRIC_BUDGET_S),
        interval_s=15.0,
        description="A's series and the account-level series covering every burst minute",
    )
    alloc_after = _allocated(lam)
    lo, hi = min(alloc_before, alloc_after), max(alloc_before, alloc_after)
    assert lo >= _RESERVED + _PC, (
        f"listed allocated concurrency {alloc_before!r}/{alloc_after!r} does not include this "
        f"check's reserved {_RESERVED} + provisioned {_PC}"
    )

    a_max = max(seen["aconc"].values())
    assert a_max == float(_BURST_A), (
        f"ConcurrentExecutions Maximum for {fn_a} (reserved {_RESERVED}) is {a_max!r}, expected "
        f"exactly {_BURST_A}; by minute {_fmt(seen['aconc'])}"
    )
    assert sum(seen["ainv"].values()) == float(_BURST_A), (
        f"Invocations Sum for {fn_a} is {sum(seen['ainv'].values())!r}, expected {_BURST_A}"
    )
    assert seen["athr"] == {} or sum(seen["athr"].values()) == 0.0, (
        f"{fn_a} took {_BURST_A} invokes under reservation {_RESERVED} yet shows Throttles "
        f"{_fmt(seen['athr'])}"
    )

    for minute in sorted(burst_minutes):
        unres = seen["unres"][minute]
        claim = seen["claim"][minute]
        assert unres >= float(_BURST_B), (
            f"UnreservedConcurrentExecutions Maximum at {minute:%H:%M} is {unres!r}; the "
            f"{_BURST_B}-way burst of the unreserved function ran then "
            f"(series {_fmt(seen['unres'])})"
        )
        assert lo <= claim - unres <= hi, (
            f"at {minute:%H:%M} ClaimedAccountConcurrency {claim!r} - "
            f"UnreservedConcurrentExecutions {unres!r} = {claim - unres!r}, expected the listed "
            f"allocated concurrency (reserved + provisioned) in [{lo}, {hi}]; claimed "
            f"{_fmt(seen['claim'])}, unreserved {_fmt(seen['unres'])}"
        )


def _allocated(lam) -> int:
    """Account allocated concurrency as Lambda itself lists it: each function's reserved
    concurrency, or, for a function with none, the sum of its provisioned allocations."""
    total = 0
    for page in lam.get_paginator("list_functions").paginate():
        for f in page["Functions"]:
            name = f["FunctionName"]
            reserved = lam.get_function_concurrency(FunctionName=name).get(
                "ReservedConcurrentExecutions"
            )
            if reserved is not None:
                total += reserved
                continue
            for pc_page in lam.get_paginator("list_provisioned_concurrency_configs").paginate(
                FunctionName=name
            ):
                total += sum(
                    c.get("RequestedProvisionedConcurrentExecutions", 0)
                    for c in pc_page["ProvisionedConcurrencyConfigs"]
                )
    return total


def _fmt(series: dict) -> str:
    return "{" + ", ".join(f"{t:%H:%M}: {v}" for t, v in sorted(series.items())) + "}"


def _budget_s(ctx, cap_s: float) -> float:
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 10 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 10.0))


def _delete_dashboards(cw, prefix: str) -> None:
    """Delete the rendezvous dashboards the burst registered under ``prefix``."""
    names, kw = [], {"DashboardNamePrefix": prefix}
    while True:
        page = cw.list_dashboards(**kw)
        names.extend(d["DashboardName"] for d in page.get("DashboardEntries", []))
        if not page.get("NextToken"):
            break
        kw["NextToken"] = page["NextToken"]
    for i in range(0, len(names), 100):
        cw.delete_dashboards(DashboardNames=names[i:i + 100])


def _minute_floor(t: datetime) -> datetime:
    return t.replace(second=0, microsecond=0)


def _read(cw, queries: dict, start: datetime) -> dict:
    """GetMetricData over [start, now+2m) at 60 s; returns id -> {minute timestamp: value}."""
    q = [
        {
            "Id": qid,
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/Lambda",
                    "MetricName": metric,
                    "Dimensions": [{"Name": k, "Value": v} for k, v in dims],
                },
                "Period": 60,
                "Stat": stat,
            },
            "ReturnData": True,
        }
        for qid, (metric, dims, stat) in queries.items()
    ]
    out: dict = {qid: {} for qid in queries}
    kwargs = {
        "MetricDataQueries": q,
        "StartTime": start,
        "EndTime": datetime.now(timezone.utc) + timedelta(minutes=2),
    }
    while True:
        resp = cw.get_metric_data(**kwargs)
        for r in resp["MetricDataResults"]:
            for ts, v in zip(r["Timestamps"], r["Values"]):
                out[r["Id"]][_minute_floor(ts.astimezone(timezone.utc))] = float(v)
        if not resp.get("NextToken"):
            return out
        kwargs["NextToken"] = resp["NextToken"]


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, src in files.items():
            zf.writestr(path, src)
    return buf.getvalue()


def _role(ctx, rv_prefix: str) -> str:
    """An execution role with NO CloudWatch Logs permission, on purpose: the metrics under test
    are published by the Lambda service, and a role that cannot create a log group leaves no
    /aws/lambda/<fn> group behind. It may only register and list rendezvous dashboards."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-olam-role-")[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__lambda"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="rendezvous",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "cloudwatch:PutDashboard",
                        "Resource": f"arn:aws:cloudwatch::*:dashboard/{rv_prefix}*",
                    },
                    {"Effect": "Allow", "Action": "cloudwatch:ListDashboards", "Resource": "*"},
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="rendezvous"))
    return arn


def _function(ctx, lam, role_arn: str, label: str, **extra) -> str:
    from botocore.exceptions import ClientError

    name = ctx.unique_name(f"sim2real-olam-{label}-")[:64]
    logs = ctx.client("logs")
    # Registered BEFORE the create so LIFO runs it AFTER delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + _ROLE_PROPAGATION_BUDGET_S
    while True:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="handler.handler",
                Code={"ZipFile": _zip({"handler.py": _HANDLER})},
                Timeout=60,
                MemorySize=128,
                Tags={"sim2real": "cloudwatch__lambda"},
                **extra,
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateFunction {name} kept refusing the fresh role for "
                    f"{_ROLE_PROPAGATION_BUDGET_S}s: {exc!r}"
                ) from exc
            time.sleep(5.0)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(
        FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60}
    )
    return name


def _reap_log_group(logs, group: str) -> None:
    """delete_function leaves the log group, and a late flush can recreate it — so delete in a
    bounded loop until a quiet read confirms it is gone."""
    from botocore.exceptions import ClientError

    for _ in range(4):
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(5.0)
        found = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        if not any(g["logGroupName"] == group for g in found):
            return
    raise AssertionError(f"log group {group} kept reappearing after deletion")


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last read {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
