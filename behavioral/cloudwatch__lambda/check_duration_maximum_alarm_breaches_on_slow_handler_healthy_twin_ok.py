"""duration-maximum-alarm-breaches-on-slow-handler-healthy-twin-ok."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duration-maximum-alarm-breaches-on-slow-handler-healthy-twin-ok"
GROUP = "alerting"
SERVICES = ["cloudwatch", "lambda"]

_ROLE_PROPAGATION_BUDGET_S = 120.0
_METRIC_BUDGET_S = 300.0
_SLEEP_MS = 6000
_THRESHOLD_MS = 3000.0
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."

_SLOW_HANDLER = (
    "exports.handler = async (event) => {\n"
    f"  await new Promise((resolve) => setTimeout(resolve, {_SLEEP_MS}));\n"
    "  return { ok: true };\n"
    "};\n"
)
_FAST_HANDLER = (
    "exports.handler = async (event) => {\n"
    "  return { ok: true };\n"
    "};\n"
)


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:happy-path",
    "cap:c4",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """An alarm on AWS/Lambda Duration's Maximum breaches from real invokes of a handler that
    sleeps past the threshold, while an identical alarm on a fast twin settles into OK.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-alarms.html
    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html
    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_DescribeAlarmHistory.html
    """
    cw = ctx.client("cloudwatch")
    lam = ctx.client("lambda")

    role_arn = _role(ctx)
    slow_fn = _function(ctx, lam, role_arn, _SLOW_HANDLER, "slow")
    fast_fn = _function(ctx, lam, role_arn, _FAST_HANDLER, "fast")

    slow_alarm = ctx.unique_name("sim2real-xsvc-cwdur-slow-")
    cw.put_metric_alarm(
        AlarmName=slow_alarm,
        Namespace="AWS/Lambda",
        MetricName="Duration",
        Dimensions=[{"Name": "FunctionName", "Value": slow_fn}],
        Statistic="Maximum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=_THRESHOLD_MS,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__lambda"}],
    )
    ctx.on_cleanup(_teardown(lambda: cw.delete_alarms(AlarmNames=[slow_alarm])))
    fast_alarm = ctx.unique_name("sim2real-xsvc-cwdur-fast-")
    cw.put_metric_alarm(
        AlarmName=fast_alarm,
        Namespace="AWS/Lambda",
        MetricName="Duration",
        Dimensions=[{"Name": "FunctionName", "Value": fast_fn}],
        Statistic="Maximum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=_THRESHOLD_MS,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__lambda"}],
    )
    ctx.on_cleanup(_teardown(lambda: cw.delete_alarms(AlarmNames=[fast_alarm])))

    fast_states: list[str] = []

    def _states() -> dict[str, str]:
        resp = cw.describe_alarms(AlarmNames=[slow_alarm, fast_alarm], AlarmTypes=["MetricAlarm"])
        got = {a["AlarmName"]: a["StateValue"] for a in resp["MetricAlarms"]}
        if fast_alarm in got:
            fast_states.append(got[fast_alarm])
        assert got.get(fast_alarm) != "ALARM", (
            f"the fast twin's alarm {fast_alarm!r} entered ALARM although {fast_fn!r} never ran "
            f"past {_THRESHOLD_MS!r}ms; states observed so far: {fast_states!r}"
        )
        return got

    # ---- drive real invokes: the slow function sleeps past the threshold, the fast twin never does
    # One invoke each is enough: a Maximum alarm breaches on its single over-threshold datapoint.
    resp = lam.invoke(FunctionName=slow_fn, Payload=b"{}")
    payload = resp["Payload"].read()
    assert resp.get("FunctionError") is None, f"the slow function raised: {payload!r}"
    resp = lam.invoke(FunctionName=fast_fn, Payload=b"{}")
    payload = resp["Payload"].read()
    assert resp.get("FunctionError") is None, f"the fast twin raised: {payload!r}"

    # The fast twin's Duration series is genuinely live (real sub-threshold datapoints), so its
    # alarm staying out of ALARM is not a channel that never carried telemetry.
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    _poll(
        ctx,
        lambda: _stats(cw, fast_fn, since),
        lambda dps: bool(dps),
        _budget_s(ctx, _METRIC_BUDGET_S),
        f"a real AWS/Lambda Duration datapoint under FunctionName={fast_fn!r}",
    )

    _poll(
        ctx,
        _states,
        lambda s: s.get(fast_alarm) == "OK",
        _budget_s(ctx, _METRIC_BUDGET_S),
        f"alarm {fast_alarm!r} to settle into OK from real sub-threshold AWS/Lambda Duration on {fast_fn!r}",
    )

    # ---- the slow function's alarm reaches ALARM from real Duration datapoints ----------------
    # Polled through DescribeAlarmHistory, not the alarm's current StateValue: with
    # EvaluationPeriods=1 the ALARM can already have settled back to OK by the time a fixed-interval
    # current-state poll looks, so only the permanent history record proves the transition happened.
    def _slow_history() -> list[dict]:
        _states()  # keep asserting the twin never alarms while we wait on the slow alarm's history
        return _transitions(cw, slow_alarm)

    transitions = _poll(
        ctx,
        _slow_history,
        lambda ts: any(t["new"] == "ALARM" and t["old"] in ("OK", "INSUFFICIENT_DATA") for t in ts),
        _budget_s(ctx, _METRIC_BUDGET_S),
        f"alarm {slow_alarm!r} to record an ALARM transition from real AWS/Lambda Duration on {slow_fn!r}",
    )
    breached = cw.describe_alarms(AlarmNames=[slow_alarm], AlarmTypes=["MetricAlarm"])["MetricAlarms"][0]
    breached_dims = {d["Name"]: d["Value"] for d in breached["Dimensions"]}
    assert breached_dims == {"FunctionName": slow_fn}, (
        f"the breached alarm's Dimensions are {breached_dims!r}, expected FunctionName={slow_fn!r}"
    )
    assert breached["MetricName"] == "Duration" and breached["Statistic"] == "Maximum", (
        f"the breached alarm grades {breached['MetricName']!r}/{breached['Statistic']!r}, "
        f"expected Duration/Maximum"
    )
    assert any(t["new"] == "ALARM" and t["old"] in ("OK", "INSUFFICIENT_DATA") for t in transitions), (
        f"alarm {slow_alarm!r} history {transitions!r} lacks a transition into ALARM"
    )

    # ---- the control: the fast twin's identically-shaped alarm never alarmed -------------------
    final = _states()
    assert final.get(fast_alarm) == "OK", f"the fast twin's alarm {fast_alarm!r} ended {final.get(fast_alarm)!r}"
    assert set(fast_states) <= {"OK", "INSUFFICIENT_DATA"}, (
        f"the fast twin's alarm was observed in states {fast_states!r}"
    )
    fast_transitions = _transitions(cw, fast_alarm)
    assert all(t["new"] != "ALARM" for t in fast_transitions), (
        f"the fast twin's alarm {fast_alarm!r} history records an ALARM transition: {fast_transitions!r}"
    )


def _zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, src in files.items():
            zf.writestr(path, src)
    return buf.getvalue()


def _role(ctx) -> str:
    """An execution role with NO permissions at all: both functions only compute, and a role that
    cannot write CloudWatch Logs means no /aws/lambda/<fn> log group is left behind for either."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-cwdur-role-")[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=(
            '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
            '"Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
        ),
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__lambda"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _function(ctx, lam, role_arn: str, handler_src: str, suffix: str) -> str:
    name = ctx.unique_name(f"sim2real-xsvc-cwdur-{suffix}-")[:64]
    deadline = time.monotonic() + _ROLE_PROPAGATION_BUDGET_S
    while True:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="nodejs22.x",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": _zip({"index.js": handler_src})},
                Timeout=15,
                MemorySize=128,
                Tags={"sim2real": "cloudwatch__lambda"},
            )
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"]["Message"]
            if code != "InvalidParameterValueException" or message != _ROLE_NOT_READY:
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"CreateFunction {name} kept refusing the fresh role: {exc!r}") from exc
            time.sleep(5.0)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    return name


def _stats(cw, fn_name: str, since: datetime) -> list[dict]:
    return cw.get_metric_statistics(
        Namespace="AWS/Lambda",
        MetricName="Duration",
        Dimensions=[{"Name": "FunctionName", "Value": fn_name}],
        StartTime=since,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
        Period=60,
        Statistics=["Maximum"],
    )["Datapoints"]


def _transitions(cw, name: str) -> list[dict]:
    out = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
        AlarmName=name, HistoryItemType="StateUpdate", AlarmTypes=["MetricAlarm"]
    ):
        for item in page["AlarmHistoryItems"]:
            data = json.loads(item["HistoryData"])
            out.append({"old": data["oldState"]["stateValue"], "new": data["newState"]["stateValue"]})
    return out


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, fetch, pred, budget_s: float, what: str):
    deadline = time.monotonic() + budget_s
    last = None
    while True:
        last = fetch()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(f"timed out after {budget_s:.0f}s waiting for {what}; last={last!r}")
        time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
