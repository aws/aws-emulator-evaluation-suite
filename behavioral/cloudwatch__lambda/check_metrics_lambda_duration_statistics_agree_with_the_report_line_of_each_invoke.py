"""metrics-lambda-duration-statistics-agree-with-the-report-line-of-each-invoke."""
from __future__ import annotations

import base64
import io
import json
import re
import time
import zipfile
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-lambda-duration-statistics-agree-with-the-report-line-of-each-invoke"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "lambda"]

_INVOKES = 4
_SLEEP_MS = 150
_METRIC_BUDGET_S = 240.0
_ROLE_PROPAGATION_BUDGET_S = 120.0

_REPORT_RE = re.compile(
    r"REPORT RequestId: (?P<rid>\S+)\s+Duration: (?P<dur>[0-9.]+) ms\s+"
    r"Billed Duration: (?P<billed>[0-9]+) ms"
)

_HANDLER = '''
import time


def handler(event, context):
    time.sleep(event.get("sleep_ms", 0) / 1000.0)
    if event.get("fail"):
        raise RuntimeError("sim2real deliberate failure")
    return {"ok": True}
'''


@tags("cap:c3", "concern:metrics", "concern:data-plane", "dp:api", "plane:data", "axis:happy-path")
def run(ctx) -> None:
    """After four sequential invokes, AWS/Lambda Duration (Milliseconds) has SampleCount 4 and a
    Sum, Maximum and Minimum matching the REPORT lines of those invokes, Invocations Sum is 4 and
    ConcurrentExecutions peaks at exactly 1."""
    start = datetime.now(timezone.utc) - timedelta(minutes=2)
    lam = ctx.client("lambda")
    cw = ctx.client("cloudwatch")

    role_arn = _role(ctx)
    fn = _function(ctx, lam, role_arn, "dur")
    dims = [("FunctionName", fn)]

    reported: list[float] = []
    for _ in range(_INVOKES):
        r = lam.invoke(
            FunctionName=fn,
            Payload=json.dumps({"sleep_ms": _SLEEP_MS}).encode(),
            LogType="Tail",
        )
        assert r.get("FunctionError") is None, f"invoke failed: {r.get('FunctionError')!r}"
        tail = base64.b64decode(r["LogResult"]).decode("utf-8", "replace")
        m = _REPORT_RE.search(tail)
        assert m, f"no REPORT line in the LogType=Tail result: {tail[-600:]!r}"
        dur, billed = float(m.group("dur")), int(m.group("billed"))
        assert dur >= _SLEEP_MS, f"REPORT Duration {dur!r} ms is below the {_SLEEP_MS} ms sleep"
        assert dur <= billed, f"REPORT Duration {dur!r} ms exceeds Billed Duration {billed!r} ms"
        reported.append(dur)

    stats = ["SampleCount", "Sum", "Minimum", "Maximum"]

    def _dur_stats():
        dps = _series(cw, "Duration", dims, start, stats)
        if not dps:
            return None
        return {
            "SampleCount": sum(d["SampleCount"] for d in dps),
            "Sum": sum(d["Sum"] for d in dps),
            "Minimum": min(d["Minimum"] for d in dps),
            "Maximum": max(d["Maximum"] for d in dps),
            "Units": {d["Unit"] for d in dps},
        }

    got = _poll_until(
        _dur_stats,
        lambda v: v is not None and v["SampleCount"] >= _INVOKES,
        timeout_s=_METRIC_BUDGET_S,
        interval_s=15.0,
        description=f"AWS/Lambda Duration SampleCount for {fn} reaching {_INVOKES}",
    )
    assert got["Units"] == {"Milliseconds"}, f"Duration Unit(s) {got['Units']!r}"
    assert got["SampleCount"] == float(_INVOKES), (
        f"Duration SampleCount is {got['SampleCount']!r}; {_INVOKES} invokes were made"
    )
    assert got["Minimum"] >= _SLEEP_MS, (
        f"Duration Minimum {got['Minimum']!r} ms is below the handler's {_SLEEP_MS} ms sleep"
    )
    tol = 0.006 * _INVOKES
    assert abs(got["Sum"] - sum(reported)) <= tol, (
        f"Duration Sum {got['Sum']!r} != sum of REPORT durations {sum(reported)!r} ({reported!r})"
    )
    assert abs(got["Maximum"] - max(reported)) <= 0.006, (
        f"Duration Maximum {got['Maximum']!r} != max REPORT duration {max(reported)!r}"
    )
    assert abs(got["Minimum"] - min(reported)) <= 0.006, (
        f"Duration Minimum {got['Minimum']!r} != min REPORT duration {min(reported)!r}"
    )

    inv = _sum(cw, "Invocations", dims, start)
    assert inv == float(_INVOKES), f"Invocations Sum for {fn} is {inv!r}, expected {_INVOKES}"

    conc = _poll_until(
        lambda: _series(cw, "ConcurrentExecutions", dims, start, ["Maximum"]),
        lambda v: bool(v),
        timeout_s=_METRIC_BUDGET_S,
        interval_s=15.0,
        description=f"AWS/Lambda ConcurrentExecutions for {fn}",
    )
    peak = max(d["Maximum"] for d in conc)
    units = {d["Unit"] for d in conc}
    assert units == {"Count"}, f"ConcurrentExecutions Unit(s) {units!r}"
    assert peak == 1.0, (
        f"ConcurrentExecutions Maximum for {fn} is {peak!r}; the {_INVOKES} synchronous invokes "
        f"were strictly sequential, so at most one execution was ever in flight"
    )


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
