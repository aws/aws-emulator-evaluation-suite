"""obs-lambda-1-provisioned-concurrency-metrics-split-served-from-spillover."""
from __future__ import annotations

import io
import json
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "obs-lambda-1-provisioned-concurrency-metrics-split-served-from-spillover"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "lambda"]

_PC = 2
_SEQUENTIAL = 2
_BURST = 4
_RENDEZVOUS_S = 30
_PC_READY_BUDGET_S = 420.0
_METRIC_BUDGET_S = 300.0
_ROLE_PROPAGATION_BUDGET_S = 120.0

_PC_METRICS = (
    "Invocations",
    "ProvisionedConcurrencyInvocations",
    "ProvisionedConcurrencySpilloverInvocations",
    "ProvisionedConcurrencyUtilization",
    "ProvisionedConcurrentExecutions",
)

_HANDLER = '''
import json
import os
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
    return {"init": os.environ.get("AWS_LAMBDA_INITIALIZATION_TYPE"), "met": met}
'''


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-types.html
@tags("cap:c3", "concern:metrics", "concern:data-plane", "dp:api", "plane:data", "axis:happy-path", "timing:real-time")
def run(ctx) -> None:
    """A PC=2 alias books provisioned-served invokes and the spillover of a 4-way rendezvous burst
    into disjoint metrics whose sums match each invoke's reported init type; an idle twin PC alias
    publishes no series.
    """
    start = _minute_floor(datetime.now(timezone.utc) - timedelta(minutes=1))
    lam = ctx.client("lambda")
    cw = ctx.client("cloudwatch")

    rv_prefix = ctx.unique_name("sim2real-olam-rv-")
    ctx.on_cleanup(lambda: _delete_dashboards(cw, rv_prefix))
    role_arn = _role(ctx, rv_prefix)
    fn = _function(ctx, lam, role_arn, "pc")

    v_live = lam.publish_version(FunctionName=fn)["Version"]
    # A configuration change, so the second PublishVersion yields a distinct version.
    lam.update_function_configuration(FunctionName=fn, Description="sim2real idle twin")
    lam.get_waiter("function_updated_v2").wait(
        FunctionName=fn, WaiterConfig={"Delay": 2, "MaxAttempts": 60}
    )
    v_idle = lam.publish_version(FunctionName=fn)["Version"]
    assert v_live != v_idle, f"PublishVersion returned the same version twice: {v_live!r}"

    lam.create_alias(FunctionName=fn, Name="live", FunctionVersion=v_live)
    ctx.on_cleanup(lambda: lam.delete_alias(FunctionName=fn, Name="live"))
    lam.create_alias(FunctionName=fn, Name="idle", FunctionVersion=v_idle)
    ctx.on_cleanup(lambda: lam.delete_alias(FunctionName=fn, Name="idle"))

    for alias in ("live", "idle"):
        lam.put_provisioned_concurrency_config(
            FunctionName=fn, Qualifier=alias, ProvisionedConcurrentExecutions=_PC
        )
        ctx.on_cleanup(
            lambda a=alias: lam.delete_provisioned_concurrency_config(FunctionName=fn, Qualifier=a)
        )
    ready = _poll_until(
        lambda: {
            a: lam.get_provisioned_concurrency_config(FunctionName=fn, Qualifier=a)
            for a in ("live", "idle")
        },
        lambda got: all(c["Status"] in ("READY", "FAILED") for c in got.values()),
        timeout_s=_budget_s(ctx, _PC_READY_BUDGET_S),
        interval_s=10.0,
        description="both aliases' provisioned concurrency leaving IN_PROGRESS",
    )
    for alias, cfg in ready.items():
        assert cfg["Status"] == "READY", f"PC on {alias} ended {cfg['Status']!r}: {cfg!r}"
        assert cfg["AllocatedProvisionedConcurrentExecutions"] == _PC, (
            f"PC on {alias} allocated {cfg['AllocatedProvisionedConcurrentExecutions']!r}, "
            f"requested {_PC}"
        )

    # Sequential, so each request finds a free provisioned environment.
    for i in range(_SEQUENTIAL):
        body = _invoke(lam, fn, "live", {})
        assert body["init"] == "provisioned-concurrency", (
            f"sequential invoke {i} on a READY PC={_PC} alias ran on {body['init']!r}"
        )

    live_dims = [("FunctionName", fn), ("Resource", f"{fn}:live")]
    idle_dims = [("FunctionName", fn), ("Resource", f"{fn}:idle")]

    def _live_sums():
        return _read(
            cw,
            {
                "inv": ("Invocations", live_dims, "Sum"),
                "pci": ("ProvisionedConcurrencyInvocations", live_dims, "Sum"),
                "spill": ("ProvisionedConcurrencySpilloverInvocations", live_dims, "Sum"),
                "util": ("ProvisionedConcurrencyUtilization", live_dims, "Maximum"),
            },
            start,
        )

    phase1 = _poll_until(
        _live_sums,
        lambda got: _total(got["pci"]) >= _SEQUENTIAL and _total(got["inv"]) >= _SEQUENTIAL,
        timeout_s=_budget_s(ctx, _METRIC_BUDGET_S),
        interval_s=15.0,
        description=f"the live alias's PC series reaching {_SEQUENTIAL} sequential invokes",
    )
    assert _total(phase1["pci"]) == float(_SEQUENTIAL), (
        f"ProvisionedConcurrencyInvocations Sum after phase 1 is {_total(phase1['pci'])!r}, "
        f"expected exactly {_SEQUENTIAL}; read {phase1!r}"
    )
    assert _total(phase1["inv"]) == float(_SEQUENTIAL), (
        f"alias Invocations Sum after phase 1 is {_total(phase1['inv'])!r}, expected exactly "
        f"{_SEQUENTIAL}; read {phase1!r}"
    )
    assert _total(phase1["spill"]) == 0.0, (
        f"ProvisionedConcurrencySpilloverInvocations Sum after {_SEQUENTIAL} sequential invokes "
        f"on PC={_PC} is {_total(phase1['spill'])!r}, expected 0; read {phase1!r}"
    )

    # A rendezvous burst wider than the allocation: all of it in flight at once must spill over.
    event = {"rv_prefix": rv_prefix, "n": _BURST, "wait_s": _RENDEZVOUS_S}
    with ThreadPoolExecutor(max_workers=_BURST) as pool:
        burst = list(pool.map(lambda _: _invoke(lam, fn, "live", event), range(_BURST)))
    unmet = [b for b in burst if b.get("met") is not True]
    assert not unmet, (
        f"{len(unmet)} of {_BURST} burst invokes never saw all {_BURST} registered within "
        f"{_RENDEZVOUS_S}s (the target must run them concurrently); bodies {burst!r}"
    )
    on_demand = sum(1 for b in burst if b["init"] == "on-demand")
    provisioned = sum(1 for b in burst if b["init"] == "provisioned-concurrency")
    assert on_demand + provisioned == _BURST, f"unexpected init types {[b['init'] for b in burst]!r}"
    assert on_demand == _BURST - _PC, (
        f"{_BURST} overlapping invokes on PC={_PC} ran {on_demand} on on-demand environments, "
        f"expected {_BURST - _PC}; init types {[b['init'] for b in burst]!r}"
    )

    total = _SEQUENTIAL + _BURST
    final = _poll_until(
        _live_sums,
        lambda got: _total(got["inv"]) >= total
        and _total(got["pci"]) + _total(got["spill"]) >= total,
        timeout_s=_budget_s(ctx, _METRIC_BUDGET_S),
        interval_s=15.0,
        description=f"the live alias's series reaching all {total} invokes",
    )
    assert _total(final["spill"]) == float(on_demand), (
        f"ProvisionedConcurrencySpilloverInvocations Sum over both phases is "
        f"{_total(final['spill'])!r}, expected exactly {on_demand} (the burst invokes that ran "
        f"on-demand); read {final!r}"
    )
    assert _total(final["spill"]) >= 1.0, (
        f"a {_BURST}-way burst on PC={_PC} booked no spillover; read {final!r}"
    )
    assert _total(final["pci"]) == float(_SEQUENTIAL + provisioned), (
        f"ProvisionedConcurrencyInvocations Sum over both phases is {_total(final['pci'])!r}, "
        f"expected exactly {_SEQUENTIAL + provisioned}; read {final!r}"
    )
    assert _total(final["inv"]) == float(total), (
        f"alias Invocations Sum over both phases is {_total(final['inv'])!r}, expected exactly "
        f"{total}; read {final!r}"
    )
    assert final["util"], f"no ProvisionedConcurrencyUtilization datapoint for {fn}:live"
    util_max = max(final["util"])
    assert 0.0 < util_max <= 1.0, (
        f"ProvisionedConcurrencyUtilization Maximum is {util_max!r}, expected in (0, 1]; "
        f"values {final['util']!r}"
    )

    # Read after the live alias's series for the same minutes are complete, so absence is not lag.
    idle = _read(cw, {f"m{i}": (m, idle_dims, "Sum") for i, m in enumerate(_PC_METRICS)}, start)
    present = {_PC_METRICS[int(k[1:])]: v for k, v in idle.items() if v}
    assert present == {}, (
        f"the never-invoked PC={_PC} alias {fn}:idle has AWS/Lambda datapoints {present!r}; an "
        f"idle allocation must publish no series"
    )
    # Positive control for the absence: the same query shape against the live alias is non-empty.
    live_again = _read(
        cw, {f"m{i}": (m, live_dims, "Sum") for i, m in enumerate(_PC_METRICS)}, start
    )
    assert _total(live_again["m0"]) == float(total), (
        f"the same query shape against the live alias read Invocations {live_again['m0']!r}"
    )


def _invoke(lam, fn: str, qualifier: str, payload: dict) -> dict:
    r = lam.invoke(FunctionName=fn, Qualifier=qualifier, Payload=json.dumps(payload).encode())
    raw = r["Payload"].read()
    assert r["StatusCode"] == 200 and r.get("FunctionError") is None, (
        f"invoke {fn}:{qualifier} returned {r['StatusCode']!r} {r.get('FunctionError')!r} {raw!r}"
    )
    return json.loads(raw)


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
    """GetMetricData over [start, now+2m) at 60 s; returns id -> list of datapoint values."""
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
    out: dict = {qid: [] for qid in queries}
    kwargs = {
        "MetricDataQueries": q,
        "StartTime": start,
        "EndTime": datetime.now(timezone.utc) + timedelta(minutes=2),
    }
    while True:
        resp = cw.get_metric_data(**kwargs)
        for r in resp["MetricDataResults"]:
            out[r["Id"]].extend(float(v) for v in r["Values"])
        if not resp.get("NextToken"):
            return out
        kwargs["NextToken"] = resp["NextToken"]


def _total(values: list[float]) -> float:
    return float(sum(values))


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
