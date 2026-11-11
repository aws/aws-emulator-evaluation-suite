"""metrics-lambda-reserved-zero-throttles-without-invocations-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-lambda-reserved-zero-throttles-without-invocations-rejected"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "lambda"]

_REFUSED = 3
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
    """With reserved concurrency 0 every invoke fails with TooManyRequestsException (429, 'Rate
    Exceeded.') and is metered as a Throttle only, with no Invocations or Duration; clearing the
    reservation admits one invoke, giving Invocations 1 and unchanged Throttles."""
    from botocore.config import Config
    from botocore.exceptions import ClientError

    start = datetime.now(timezone.utc) - timedelta(minutes=2)
    # No SDK retries: every refused request must be exactly one request at the service.
    lam = ctx.client("lambda", config=Config(retries={"total_max_attempts": 1}))
    cw = ctx.client("cloudwatch")

    role_arn = _role(ctx)
    fn = _function(ctx, lam, role_arn, "zero")
    dims = [("FunctionName", fn)]

    lam.put_function_concurrency(FunctionName=fn, ReservedConcurrentExecutions=0)
    ctx.on_cleanup(lambda: lam.delete_function_concurrency(FunctionName=fn))
    got = lam.get_function_concurrency(FunctionName=fn).get("ReservedConcurrentExecutions")
    assert got == 0, f"GetFunctionConcurrency for {fn} reports {got!r}, expected 0"

    for _ in range(_REFUSED):
        try:
            resp = lam.invoke(FunctionName=fn, Payload=b"{}")
        except ClientError as exc:
            err = exc.response
        else:
            raise AssertionError(
                f"invoke of {fn} with reserved concurrency 0 was ACCEPTED "
                f"(StatusCode {resp['StatusCode']!r}); it must be refused"
            )
        code = err["Error"]["Code"]
        assert code == "TooManyRequestsException", (
            f"reserved-0 invoke of {fn} failed with {code!r}, expected TooManyRequestsException"
        )
        message = err["Error"].get("Message")
        assert message == "Rate Exceeded.", (
            f"reserved-0 refusal of {fn} carried message {message!r}, expected 'Rate Exceeded.'"
        )
        assert err["ResponseMetadata"]["HTTPStatusCode"] == 429, (
            f"reserved-0 refusal carried HTTP {err['ResponseMetadata']['HTTPStatusCode']!r}"
        )
        assert err.get("Reason") == "ReservedFunctionConcurrentInvocationLimitExceeded", (
            f"reserved-0 refusal Reason was {err.get('Reason')!r}"
        )

    throttles = _poll_until(
        lambda: _sum(cw, "Throttles", dims, start),
        lambda v: v is not None and v >= _REFUSED,
        timeout_s=_METRIC_BUDGET_S,
        interval_s=15.0,
        description=f"AWS/Lambda Throttles for [FunctionName={fn}] reaching {_REFUSED}",
    )
    assert throttles == float(_REFUSED), (
        f"AWS/Lambda Throttles Sum for {fn} is {throttles!r}; exactly {_REFUSED} requests were "
        f"refused and SDK retries were off"
    )
    units = {d["Unit"] for d in _series(cw, "Throttles", dims, start, ["Sum"])}
    assert units == {"Count"}, f"Throttles for {fn} carries Unit(s) {units!r}"

    # Effect ABSENT: the refused requests never ran, so there is no Invocations or Duration series.
    _assert_stays(
        lambda: (_sum(cw, "Invocations", dims, start), _sum(cw, "Duration", dims, start)),
        (None, None),
        hold_s=_ABSENCE_HOLD_S,
        description=(
            f"Invocations and Duration for [FunctionName={fn}] after {_REFUSED} throttled "
            f"requests (Throttles already visible at {throttles!r})"
        ),
    )

    # Positive control: lift the reservation, one invoke runs, and it is metered as one Invocation.
    lam.delete_function_concurrency(FunctionName=fn)
    resp = lam.invoke(FunctionName=fn, Payload=b"{}")
    body = json.loads(resp["Payload"].read())
    assert resp["StatusCode"] == 200 and body == {"ok": True}, (
        f"after DeleteFunctionConcurrency the invoke returned {resp['StatusCode']!r} {body!r}"
    )
    invocations = _poll_until(
        lambda: _sum(cw, "Invocations", dims, start),
        lambda v: v is not None and v >= 1.0,
        timeout_s=_METRIC_BUDGET_S,
        interval_s=15.0,
        description=f"AWS/Lambda Invocations for {fn} reaching 1 after the reservation was lifted",
    )
    assert invocations == 1.0, f"Invocations Sum for {fn} is {invocations!r}, expected 1.0"
    final_throttles = _sum(cw, "Throttles", dims, start)
    assert final_throttles == float(_REFUSED), (
        f"Throttles Sum for {fn} moved to {final_throttles!r} after an admitted invoke; expected "
        f"it to stay {float(_REFUSED)!r}"
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
