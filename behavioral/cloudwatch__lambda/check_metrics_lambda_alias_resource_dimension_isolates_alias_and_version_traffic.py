"""metrics-lambda-alias-resource-dimension-isolates-alias-and-version-traffic."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-lambda-alias-resource-dimension-isolates-alias-and-version-traffic"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "lambda"]

_BLUE_OK = 3
_GREEN_FAIL = 1
_UNQUALIFIED = 2
_VERSION_DIRECT = 1
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
@tags("cap:c3", "concern:metrics", "concern:data-plane", "dp:api", "plane:data", "axis:happy-path", "timing:real-time")
def run(ctx) -> None:
    """AWS/Lambda books each alias, version and unqualified invoke only under its own Resource
    series (and ExecutedVersion for aliases), the FunctionName series is their total, and Errors
    follow the same split: green's failure is green's and blue's Errors Sum is 0."""
    start = datetime.now(timezone.utc) - timedelta(minutes=2)
    lam = ctx.client("lambda")
    cw = ctx.client("cloudwatch")

    role_arn = _role(ctx)
    fn = _function(ctx, lam, role_arn, "alias")

    v1 = lam.publish_version(FunctionName=fn)["Version"]
    lam.update_function_configuration(FunctionName=fn, Description="sim2real v2")
    lam.get_waiter("function_updated_v2").wait(
        FunctionName=fn, WaiterConfig={"Delay": 2, "MaxAttempts": 60}
    )
    v2 = lam.publish_version(FunctionName=fn)["Version"]
    assert v1 != v2, f"PublishVersion returned the same version twice: {v1!r}"

    lam.create_alias(FunctionName=fn, Name="blue", FunctionVersion=v1)
    ctx.on_cleanup(lambda: lam.delete_alias(FunctionName=fn, Name="blue"))
    lam.create_alias(FunctionName=fn, Name="green", FunctionVersion=v2)
    ctx.on_cleanup(lambda: lam.delete_alias(FunctionName=fn, Name="green"))

    for _ in range(_BLUE_OK):
        r = lam.invoke(FunctionName=fn, Qualifier="blue", Payload=b"{}")
        assert r.get("FunctionError") is None and r["ExecutedVersion"] == v1, (
            f"blue invoke: FunctionError {r.get('FunctionError')!r}, ExecutedVersion "
            f"{r.get('ExecutedVersion')!r} (expected {v1!r})"
        )
    for _ in range(_GREEN_FAIL):
        r = lam.invoke(FunctionName=fn, Qualifier="green", Payload=json.dumps({"fail": True}).encode())
        assert r.get("FunctionError") == "Unhandled" and r["ExecutedVersion"] == v2, (
            f"green invoke: FunctionError {r.get('FunctionError')!r}, ExecutedVersion "
            f"{r.get('ExecutedVersion')!r} (expected {v2!r})"
        )
    for _ in range(_UNQUALIFIED):
        r = lam.invoke(FunctionName=fn, Payload=b"{}")
        assert r.get("FunctionError") is None and r["ExecutedVersion"] == "$LATEST", (
            f"unqualified invoke ExecutedVersion {r.get('ExecutedVersion')!r}"
        )
    for _ in range(_VERSION_DIRECT):
        r = lam.invoke(FunctionName=fn, Qualifier=v1, Payload=b"{}")
        assert r.get("FunctionError") is None and r["ExecutedVersion"] == v1, (
            f"direct v{v1} invoke ExecutedVersion {r.get('ExecutedVersion')!r}"
        )

    total = _BLUE_OK + _GREEN_FAIL + _UNQUALIFIED + _VERSION_DIRECT
    want = {
        ("Invocations", (("FunctionName", fn), ("Resource", f"{fn}:blue"))): _BLUE_OK,
        ("Invocations", (("FunctionName", fn), ("Resource", f"{fn}:green"))): _GREEN_FAIL,
        ("Invocations", (("FunctionName", fn), ("Resource", f"{fn}:{v1}"))): _VERSION_DIRECT,
        ("Invocations", (("FunctionName", fn), ("Resource", fn))): _UNQUALIFIED,
        ("Invocations", (("FunctionName", fn),)): total,
        (
            "Invocations",
            (("FunctionName", fn), ("ExecutedVersion", v1), ("Resource", f"{fn}:blue")),
        ): _BLUE_OK,
        (
            "Invocations",
            (("FunctionName", fn), ("ExecutedVersion", v2), ("Resource", f"{fn}:green")),
        ): _GREEN_FAIL,
        ("Errors", (("FunctionName", fn), ("Resource", f"{fn}:green"))): _GREEN_FAIL,
        ("Errors", (("FunctionName", fn),)): _GREEN_FAIL,
    }
    seen = _poll_until(
        lambda: {k: _sum(cw, k[0], list(k[1]), start) for k in want},
        lambda got: all(got[k] is not None and got[k] >= v for k, v in want.items()),
        timeout_s=_METRIC_BUDGET_S,
        interval_s=15.0,
        description="every per-qualifier AWS/Lambda series reaching its invoke count",
    )
    for (metric, dims), expected in want.items():
        assert seen[(metric, dims)] == float(expected), (
            f"AWS/Lambda {metric} Sum for {dict(dims)!r} is {seen[(metric, dims)]!r}, expected "
            f"exactly {float(expected)!r} (blue={_BLUE_OK} ok, green={_GREEN_FAIL} failing, "
            f"unqualified={_UNQUALIFIED}, direct v{v1}={_VERSION_DIRECT}; all read: {seen!r})"
        )
        units = {d["Unit"] for d in _series(cw, metric, list(dims), start, ["Sum"])}
        assert units == {"Count"}, f"{metric} {dict(dims)!r} carries Unit(s) {units!r}"

    # Isolation, stated as the absence it is: blue never failed, so blue's Errors are 0 even though
    # its sibling alias on the same function did fail.
    blue_errors = _sum(cw, "Errors", [("FunctionName", fn), ("Resource", f"{fn}:blue")], start)
    assert (blue_errors or 0.0) == 0.0, (
        f"Errors Sum for Resource={fn}:blue is {blue_errors!r}; the failure was sent to green"
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
