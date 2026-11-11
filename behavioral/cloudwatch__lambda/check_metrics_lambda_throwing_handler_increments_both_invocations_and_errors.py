"""metrics-lambda-throwing-handler-increments-both-invocations-and-errors."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-lambda-throwing-handler-increments-both-invocations-and-errors"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "lambda"]

_FAILS = 3
_SUCCESSES = 2
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


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-types.html
@tags("cap:c3", "concern:metrics", "concern:data-plane", "dp:api", "plane:data", "axis:happy-path", "timing:real-time")
def run(ctx) -> None:
    """On one function driven with 3 failing and 2 succeeding invokes, Invocations Sum is 5 and
    Errors Sum is 3 (Unit Count) and Throttles 0, while a clean twin reports Errors 0: a failed
    invoke is still an invocation."""
    start = datetime.now(timezone.utc) - timedelta(minutes=2)
    lam = ctx.client("lambda")
    cw = ctx.client("cloudwatch")

    role_arn = _role(ctx)
    flaky = _function(ctx, lam, role_arn, "err")
    clean = _function(ctx, lam, role_arn, "ok")

    for _ in range(_FAILS):
        resp = lam.invoke(FunctionName=flaky, Payload=json.dumps({"fail": True}).encode())
        body = json.loads(resp["Payload"].read())
        assert resp["StatusCode"] == 200, f"failing invoke StatusCode {resp['StatusCode']!r}"
        assert resp.get("FunctionError") == "Unhandled", (
            f"a handler that raises must surface FunctionError 'Unhandled', got "
            f"{resp.get('FunctionError')!r} with body {body!r}"
        )
        assert body.get("errorType") == "RuntimeError", f"error body was {body!r}"
    for fn in (flaky, clean):
        for _ in range(_SUCCESSES):
            resp = lam.invoke(FunctionName=fn, Payload=b"{}")
            body = json.loads(resp["Payload"].read())
            assert resp.get("FunctionError") is None and body == {"ok": True}, (
                f"succeeding invoke of {fn} returned FunctionError {resp.get('FunctionError')!r} "
                f"and body {body!r}"
            )

    fn_dim = lambda fn: [("FunctionName", fn)]  # noqa: E731

    want = {
        ("Invocations", flaky): float(_FAILS + _SUCCESSES),
        ("Errors", flaky): float(_FAILS),
        ("Invocations", clean): float(_SUCCESSES),
    }
    seen = _poll_until(
        lambda: {k: _sum(cw, k[0], fn_dim(k[1]), start) for k in want},
        lambda got: all(got[k] is not None and got[k] >= v for k, v in want.items()),
        timeout_s=_METRIC_BUDGET_S,
        interval_s=15.0,
        description=f"AWS/Lambda Invocations/Errors reaching {want!r}",
    )
    for (metric, fn), expected in want.items():
        assert seen[(metric, fn)] == expected, (
            f"AWS/Lambda {metric} Sum for [FunctionName={fn}] is {seen[(metric, fn)]!r}, expected "
            f"exactly {expected!r}: {_FAILS} failing + {_SUCCESSES} succeeding invokes were made "
            f"(all read: {seen!r})"
        )

    # Units are part of the contract: both are Count.
    for metric, fn in (("Invocations", flaky), ("Errors", flaky), ("Invocations", clean)):
        units = {d["Unit"] for d in _series(cw, metric, fn_dim(fn), start, ["Sum"])}
        assert units == {"Count"}, f"AWS/Lambda {metric} for {fn} carries Unit(s) {units!r}"

    # Positive control: a function whose handler never threw reports zero Errors.
    clean_errors = _sum(cw, "Errors", fn_dim(clean), start) or 0.0
    assert clean_errors == 0.0, (
        f"AWS/Lambda Errors Sum for the clean twin {clean} is {clean_errors!r}; it never threw"
    )
    # A function error is not admission control: Throttles must stay 0 on the failing function.
    throttles = _sum(cw, "Throttles", fn_dim(flaky), start) or 0.0
    assert throttles == 0.0, (
        f"AWS/Lambda Throttles Sum for {flaky} is {throttles!r}; handler exceptions are Errors, "
        f"never Throttles"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
