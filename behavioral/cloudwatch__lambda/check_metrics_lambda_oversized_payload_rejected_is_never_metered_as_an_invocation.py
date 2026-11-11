"""metrics-lambda-oversized-payload-rejected-is-never-metered-as-an-invocation."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-lambda-oversized-payload-rejected-is-never-metered-as-an-invocation"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "lambda"]

#: The synchronous request-payload quota is a fixed API constant (6 MB), not an account quota.
_SYNC_PAYLOAD_LIMIT = 6 * 1024 * 1024
_OVERSIZED = 2
_ADMITTED = 1
_METRIC_BUDGET_S = 240.0
_ABSENCE_HOLD_S = 30.0
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
@tags(
    "axis:rejection",
    "cap:c3",
    "concern:metrics",
    "concern:negative-classes",
    "concern:data-plane",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """Invokes over the 6 MB synchronous payload limit fail with RequestEntityTooLargeException
    (HTTP 413) and are never metered: with one admitted invoke, Invocations Sum stays exactly 1 and
    Errors and Throttles stay 0."""
    from botocore.config import Config
    from botocore.exceptions import ClientError

    start = datetime.now(timezone.utc) - timedelta(minutes=2)
    lam = ctx.client("lambda", config=Config(retries={"total_max_attempts": 1}, read_timeout=120))
    cw = ctx.client("cloudwatch")

    role_arn = _role(ctx)
    fn = _function(ctx, lam, role_arn, "big")
    dims = [("FunctionName", fn)]

    big = json.dumps({"pad": "a" * (_SYNC_PAYLOAD_LIMIT + 1024)}).encode()
    assert len(big) > _SYNC_PAYLOAD_LIMIT, f"oversized payload is only {len(big)} bytes"
    for _ in range(_OVERSIZED):
        try:
            resp = lam.invoke(FunctionName=fn, Payload=big)
        except ClientError as exc:
            err = exc.response
        else:
            raise AssertionError(
                f"a {len(big)}-byte synchronous payload was ACCEPTED by {fn} "
                f"(StatusCode {resp['StatusCode']!r}); the limit is {_SYNC_PAYLOAD_LIMIT} bytes"
            )
        got = (err["Error"]["Code"], err["Error"].get("Message", ""))
        expected = (
            "RequestEntityTooLargeException",
            f"{len(big)} byte payload is too large for the RequestResponse invocation type "
            f"(limit {_SYNC_PAYLOAD_LIMIT} bytes)",
        )
        assert got == expected, f"oversized invoke failed with {got!r}, expected {expected!r}"
        assert err["ResponseMetadata"]["HTTPStatusCode"] == 413, (
            f"oversized refusal carried HTTP {err['ResponseMetadata']['HTTPStatusCode']!r}"
        )

    for _ in range(_ADMITTED):
        r = lam.invoke(FunctionName=fn, Payload=b"{}")
        body = json.loads(r["Payload"].read())
        assert r.get("FunctionError") is None and body == {"ok": True}, (
            f"positive-control invoke returned {r.get('FunctionError')!r} {body!r}"
        )

    inv = _poll_until(
        lambda: _sum(cw, "Invocations", dims, start),
        lambda v: v is not None and v >= _ADMITTED,
        timeout_s=_METRIC_BUDGET_S,
        interval_s=15.0,
        description=f"Invocations for [FunctionName={fn}] reaching the {_ADMITTED} admitted invoke",
    )
    assert inv == float(_ADMITTED), (
        f"Invocations Sum for {fn} is {inv!r}: {_ADMITTED} invoke was admitted and {_OVERSIZED} "
        f"were refused with 413, so exactly {float(_ADMITTED)!r} is correct"
    )
    _assert_stays(
        lambda: (
            _sum(cw, "Invocations", dims, start),
            _sum(cw, "Errors", dims, start) or 0.0,
            _sum(cw, "Throttles", dims, start) or 0.0,
        ),
        (float(_ADMITTED), 0.0, 0.0),
        hold_s=_ABSENCE_HOLD_S,
        description=(
            f"(Invocations, Errors, Throttles) for {fn} after {_OVERSIZED} oversized refusals "
            f"and {_ADMITTED} admitted invoke"
        ),
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
