"""concurrentexecutions-alarm-breaches-on-parallel-invokes-sequential-twin-ok."""
from __future__ import annotations

import io
import json
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrentexecutions-alarm-breaches-on-parallel-invokes-sequential-twin-ok"
GROUP = "alerting"
SERVICES = ["cloudwatch", "lambda"]

_ROLE_PROPAGATION_BUDGET_S = 120.0
_METRIC_BUDGET_S = 300.0
_PARALLEL_WAVE = 5
_SLEEP_S = 8
_THRESHOLD = 2.0
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."

_SLEEP_HANDLER = f"""
def handler(event:, context:)
  sleep({_SLEEP_S})
  {{ ok: true }}
end
"""
_FAST_HANDLER = """
def handler(event:, context:)
  { ok: true }
end
"""


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
    """An alarm on AWS/Lambda ConcurrentExecutions's Maximum breaches when real parallel invokes
    overlap on one function, while an identical alarm on a sequentially-invoked twin stays OK.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-alarms.html
    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html
    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_DescribeAlarmHistory.html
    """
    cw = ctx.client("cloudwatch")
    lam = ctx.client("lambda")

    role_arn = _role(ctx)
    pulse_fn = _function(ctx, lam, role_arn, _SLEEP_HANDLER, "pulse")
    seq_fn = _function(ctx, lam, role_arn, _FAST_HANDLER, "seq")

    pulse_alarm = ctx.unique_name("sim2real-xsvc-cwcce-pulse-")
    cw.put_metric_alarm(
        AlarmName=pulse_alarm,
        Namespace="AWS/Lambda",
        MetricName="ConcurrentExecutions",
        Dimensions=[{"Name": "FunctionName", "Value": pulse_fn}],
        Statistic="Maximum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=_THRESHOLD,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__lambda"}],
    )
    ctx.on_cleanup(_teardown(lambda: cw.delete_alarms(AlarmNames=[pulse_alarm])))
    seq_alarm = ctx.unique_name("sim2real-xsvc-cwcce-seq-")
    cw.put_metric_alarm(
        AlarmName=seq_alarm,
        Namespace="AWS/Lambda",
        MetricName="ConcurrentExecutions",
        Dimensions=[{"Name": "FunctionName", "Value": seq_fn}],
        Statistic="Maximum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=_THRESHOLD,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__lambda"}],
    )
    ctx.on_cleanup(_teardown(lambda: cw.delete_alarms(AlarmNames=[seq_alarm])))

    seq_states: list[str] = []

    def _states() -> dict[str, str]:
        resp = cw.describe_alarms(AlarmNames=[pulse_alarm, seq_alarm], AlarmTypes=["MetricAlarm"])
        got = {a["AlarmName"]: a["StateValue"] for a in resp["MetricAlarms"]}
        if seq_alarm in got:
            seq_states.append(got[seq_alarm])
        assert got.get(seq_alarm) != "ALARM", (
            f"the sequential twin's alarm {seq_alarm!r} entered ALARM although {seq_fn!r} was "
            f"never invoked more than one at a time; states observed so far: {seq_states!r}"
        )
        return got

    # ---- drive one real wave of overlapping invokes on pulse_fn --------------------------------
    with ThreadPoolExecutor(max_workers=_PARALLEL_WAVE) as pool:
        futures = [pool.submit(lam.invoke, FunctionName=pulse_fn, Payload=b"{}") for _ in range(_PARALLEL_WAVE)]
        for fut in futures:
            resp = fut.result()
            payload = resp["Payload"].read()
            assert resp.get("FunctionError") is None, f"the pulse function raised: {payload!r}"

    # ---- drive the twin strictly sequentially: one call returns before the next starts ---------
    for _ in range(3):
        resp = lam.invoke(FunctionName=seq_fn, Payload=b"{}")
        payload = resp["Payload"].read()
        assert resp.get("FunctionError") is None, f"the sequential twin raised: {payload!r}"

    # The twin's ConcurrentExecutions series is genuinely live (real Maximum=1 datapoints), so
    # its alarm staying out of ALARM is not a channel that never carried telemetry.
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    _poll(
        ctx,
        lambda: _stats(cw, seq_fn, since),
        lambda dps: bool(dps),
        _budget_s(ctx, _METRIC_BUDGET_S),
        f"a real AWS/Lambda ConcurrentExecutions datapoint under FunctionName={seq_fn!r}",
    )
    seq_max = max(float(d["Maximum"]) for d in _stats(cw, seq_fn, since))
    assert seq_max == 1.0, (
        f"the sequential twin's ConcurrentExecutions Maximum is {seq_max!r}, expected exactly 1.0"
    )

    _poll(
        ctx,
        _states,
        lambda s: s.get(seq_alarm) == "OK",
        _budget_s(ctx, _METRIC_BUDGET_S),
        f"alarm {seq_alarm!r} to settle into OK from real non-breaching ConcurrentExecutions on {seq_fn!r}",
    )

    # ---- the pulse function's alarm reaches ALARM from real overlap ----------------------------
    # Polled through DescribeAlarmHistory, not the alarm's current StateValue: with
    # EvaluationPeriods=1 the ALARM can already have settled back to OK by the time a fixed-interval
    # current-state poll looks, so only the permanent history record proves the transition happened.
    def _pulse_history() -> list[dict]:
        _states()  # keep asserting the twin never alarms while we wait on the pulse alarm's history
        return _transitions(cw, pulse_alarm)

    transitions = _poll(
        ctx,
        _pulse_history,
        lambda ts: any(t["new"] == "ALARM" and t["old"] in ("OK", "INSUFFICIENT_DATA") for t in ts),
        _budget_s(ctx, _METRIC_BUDGET_S),
        f"alarm {pulse_alarm!r} to record an ALARM transition from real AWS/Lambda ConcurrentExecutions on {pulse_fn!r}",
    )
    pulse_max = max(float(d["Maximum"]) for d in _stats(cw, pulse_fn, since))
    assert pulse_max > _THRESHOLD, (
        f"the pulse function's ConcurrentExecutions Maximum is {pulse_max!r}, expected > {_THRESHOLD!r}"
    )
    breached = cw.describe_alarms(AlarmNames=[pulse_alarm], AlarmTypes=["MetricAlarm"])["MetricAlarms"][0]
    breached_dims = {d["Name"]: d["Value"] for d in breached["Dimensions"]}
    assert breached_dims == {"FunctionName": pulse_fn}, (
        f"the breached alarm's Dimensions are {breached_dims!r}, expected FunctionName={pulse_fn!r}"
    )
    assert any(t["new"] == "ALARM" and t["old"] in ("OK", "INSUFFICIENT_DATA") for t in transitions), (
        f"alarm {pulse_alarm!r} history {transitions!r} lacks a transition into ALARM"
    )

    # ---- the control: the sequential twin's identically-shaped alarm never alarmed -------------
    final = _states()
    assert final.get(seq_alarm) == "OK", f"the sequential twin's alarm {seq_alarm!r} ended {final.get(seq_alarm)!r}"
    assert set(seq_states) <= {"OK", "INSUFFICIENT_DATA"}, (
        f"the sequential twin's alarm was observed in states {seq_states!r}"
    )
    seq_transitions = _transitions(cw, seq_alarm)
    assert all(t["new"] != "ALARM" for t in seq_transitions), (
        f"the sequential twin's alarm {seq_alarm!r} history records an ALARM transition: {seq_transitions!r}"
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
    name = ctx.unique_name("sim2real-xsvc-cwcce-role-")[:64]
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
    name = ctx.unique_name(f"sim2real-xsvc-cwcce-{suffix}-")[:64]
    deadline = time.monotonic() + _ROLE_PROPAGATION_BUDGET_S
    while True:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="ruby3.4",
                Role=role_arn,
                Handler="main.handler",
                Code={"ZipFile": _zip({"main.rb": handler_src})},
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
        MetricName="ConcurrentExecutions",
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
