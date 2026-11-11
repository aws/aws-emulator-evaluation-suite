"""metrics-lambda-async-retry-meters-every-attempt-but-each-event-once."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-lambda-async-retry-meters-every-attempt-but-each-event-once"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "lambda"]

_EVENTS = 2
_METRIC_BUDGET_S = 240.0
_ROLE_PROPAGATION_BUDGET_S = 120.0

_HANDLER = '''
import time


def handler(event, context):
    time.sleep(event.get("sleep_ms", 0) / 1000.0)
    if event.get("fail"):
        raise RuntimeError("sim2real deliberate failure")
    return {"ok": True}
'''


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics.html
@tags("cap:c3", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "axis:happy-path", "timing:real-time")
def run(ctx) -> None:
    """With MaximumRetryAttempts=1 two always-failing async events meter AsyncEventsReceived and
    AsyncEventsDropped 2 but Invocations and Errors 4 (each attempt), while a succeeding control
    with no retries meters 2 received, 2 invocations and 0 dropped and errors."""
    start = datetime.now(timezone.utc) - timedelta(minutes=2)
    lam = ctx.client("lambda")
    cw = ctx.client("cloudwatch")

    role_arn = _role(ctx)
    failing = _function(ctx, lam, role_arn, "retry")
    healthy = _function(ctx, lam, role_arn, "async")
    for fn, retries in ((failing, 1), (healthy, 0)):
        cfg = lam.put_function_event_invoke_config(FunctionName=fn, MaximumRetryAttempts=retries)
        assert cfg["MaximumRetryAttempts"] == retries, f"event invoke config echoed {cfg!r}"

    for fn, payload in ((failing, {"fail": True}), (healthy, {})):
        for _ in range(_EVENTS):
            r = lam.invoke(FunctionName=fn, InvocationType="Event", Payload=json.dumps(payload).encode())
            assert r["StatusCode"] == 202, f"async invoke of {fn} returned {r['StatusCode']!r}"
            assert r.get("FunctionError") is None, (
                f"an async caller must never see the handler's error, got {r.get('FunctionError')!r}"
            )

    attempts = _EVENTS * 2  # original + MaximumRetryAttempts=1
    want = {
        ("AsyncEventsReceived", failing): _EVENTS,
        ("AsyncEventsDropped", failing): _EVENTS,
        ("Invocations", failing): attempts,
        ("Errors", failing): attempts,
        ("AsyncEventsReceived", healthy): _EVENTS,
        ("Invocations", healthy): _EVENTS,
    }
    seen = _poll_until(
        lambda: {k: _sum(cw, k[0], [("FunctionName", k[1])], start) for k in want},
        lambda got: all(got[k] is not None and got[k] >= v for k, v in want.items()),
        timeout_s=_METRIC_BUDGET_S,
        interval_s=15.0,
        description=f"async accounting reaching {want!r} (the retry runs about a minute later)",
    )
    for (metric, fn), expected in want.items():
        label = "retrying/failing" if fn == failing else "healthy control"
        assert seen[(metric, fn)] == float(expected), (
            f"AWS/Lambda {metric} Sum for the {label} function {fn} is {seen[(metric, fn)]!r}, "
            f"expected exactly {float(expected)!r} ({_EVENTS} events, retries "
            f"{'1' if fn == failing else '0'}; all read: {seen!r})"
        )
        units = {d["Unit"] for d in _series(cw, metric, [("FunctionName", fn)], start, ["Sum"])}
        assert units == {"Count"}, f"{metric} for {fn} carries Unit(s) {units!r}"

    # Effect absent on the healthy control: nothing failed, so nothing is dropped or errored.
    for metric in ("AsyncEventsDropped", "Errors"):
        v = _sum(cw, metric, [("FunctionName", healthy)], start) or 0.0
        assert v == 0.0, f"{metric} Sum for the healthy control {healthy} is {v!r}, expected 0"


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, src in files.items():
            zf.writestr(path, src)
    return buf.getvalue()


def _role(ctx) -> str:
    """An execution role with NO CloudWatch Logs permission, on purpose: the metrics under test are
    published by the Lambda service, not by the function, and a role that cannot create a log
    group means the check leaves no /aws/lambda/<fn> group behind."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-mlam-role-")[:64]
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
    return arn


def _function(ctx, lam, role_arn: str, label: str, **extra) -> str:
    from botocore.exceptions import ClientError

    name = ctx.unique_name(f"sim2real-mlam-{label}-")[:64]
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
                Timeout=15,
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


def _series(cw, metric: str, dims: list[tuple[str, str]], start, stats: list[str]) -> list[dict]:
    return cw.get_metric_statistics(
        Namespace="AWS/Lambda",
        MetricName=metric,
        Dimensions=[{"Name": k, "Value": v} for k, v in dims],
        StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
        Period=60,
        Statistics=stats,
    )["Datapoints"]


def _sum(cw, metric: str, dims: list[tuple[str, str]], start) -> float | None:
    dps = _series(cw, metric, dims, start, ["Sum"])
    return float(sum(d["Sum"] for d in dps)) if dps else None


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last read {last!r}")


def _assert_stays(probe, expected, *, hold_s, interval_s=10.0, description="reading"):
    deadline = time.monotonic() + hold_s
    while True:
        got = probe()
        assert got == expected, (
            f"{description}: read {got!r}, expected it to stay {expected!r} for {hold_s}s"
        )
        if time.monotonic() >= deadline:
            return
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
