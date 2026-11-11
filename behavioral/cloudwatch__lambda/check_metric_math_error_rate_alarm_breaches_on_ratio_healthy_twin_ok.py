"""metric-math-error-rate-alarm-breaches-on-ratio-healthy-twin-ok."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metric-math-error-rate-alarm-breaches-on-ratio-healthy-twin-ok"
GROUP = "alerting"
SERVICES = ["cloudwatch", "lambda"]

_ROLE_PROPAGATION_BUDGET_S = 120.0
_METRIC_BUDGET_S = 300.0
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."

_FAIL_HANDLER = '''
def handler(event:, context:)
  raise "sim2real deliberate failure"
end
'''
_OK_HANDLER = '''
def handler(event:, context:)
  {ok: true}
end
'''


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
    """A metric-math alarm on errors/invocations (both Sum, period 60) reaches ALARM from a real
    error ratio of 1.0, while the same expression over a healthy twin, invoked equally often and
    never failing, whose rate is genuinely 0, never breaches.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/using-metric-math.html
    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html
    """
    cw = ctx.client("cloudwatch")
    lam = ctx.client("lambda")

    role_arn = _role(ctx)
    fail_fn = _function(ctx, lam, role_arn, _FAIL_HANDLER, "fail")
    ok_fn = _function(ctx, lam, role_arn, _OK_HANDLER, "ok")

    fail_alarm = ctx.unique_name("sim2real-xsvc-cwmm-fail-")
    cw.put_metric_alarm(
        AlarmName=fail_alarm,
        Metrics=_rate_metrics(fail_fn),
        EvaluationPeriods=1,
        Threshold=0.5,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="missing",
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__lambda"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[fail_alarm]))
    ok_alarm = ctx.unique_name("sim2real-xsvc-cwmm-ok-")
    cw.put_metric_alarm(
        AlarmName=ok_alarm,
        Metrics=_rate_metrics(ok_fn),
        EvaluationPeriods=1,
        Threshold=0.5,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="missing",
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__lambda"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[ok_alarm]))

    ok_states: list[str] = []

    def _states() -> dict[str, str]:
        resp = cw.describe_alarms(AlarmNames=[fail_alarm, ok_alarm], AlarmTypes=["MetricAlarm"])
        got = {a["AlarmName"]: a["StateValue"] for a in resp["MetricAlarms"]}
        if ok_alarm in got:
            ok_states.append(got[ok_alarm])
        assert got.get(ok_alarm) != "ALARM", (
            f"the healthy twin's error-rate alarm {ok_alarm!r} entered ALARM although {ok_fn!r} "
            f"never raised; states so far: {ok_states!r}"
        )
        return got

    for _ in range(3):
        resp = lam.invoke(FunctionName=fail_fn, Payload=b"{}")
        payload = resp["Payload"].read()
        assert resp.get("FunctionError") == "Unhandled", (
            f"the failing function returned FunctionError={resp.get('FunctionError')!r}, payload={payload!r}"
        )
    for _ in range(3):
        resp = lam.invoke(FunctionName=ok_fn, Payload=b"{}")
        payload = json.loads(resp["Payload"].read())
        assert resp.get("FunctionError") is None, f"the healthy twin raised: {payload!r}"
        assert payload == {"ok": True}, f"the healthy twin returned {payload!r}, expected {{'ok': True}}"

    since = datetime.now(timezone.utc) - timedelta(hours=1)
    _poll(
        lambda: _invocations(cw, ok_fn, since),
        lambda dps: sum(float(d["Sum"]) for d in dps) >= 3,
        _METRIC_BUDGET_S,
        f"3 real AWS/Lambda Invocations datapoints under FunctionName={ok_fn!r}",
    )
    ok_errors = sum(float(d["Sum"]) for d in _errors(cw, ok_fn, since))
    assert ok_errors == 0.0, f"AWS/Lambda Errors for the healthy twin {ok_fn!r} sums to {ok_errors!r}"

    _poll(
        _states,
        lambda s: s.get(ok_alarm) == "OK",
        _METRIC_BUDGET_S,
        f"error-rate alarm {ok_alarm!r} to settle into OK from a real 0 error rate on {ok_fn!r}",
    )

    _poll(
        _states,
        lambda s: s.get(fail_alarm) == "ALARM",
        _METRIC_BUDGET_S,
        f"error-rate alarm {fail_alarm!r} to reach ALARM from a real errors/invocations ratio on {fail_fn!r}",
    )
    transitions = _transitions(cw, fail_alarm)
    assert any(t["new"] == "ALARM" and t["old"] in ("OK", "INSUFFICIENT_DATA") for t in transitions), (
        f"error-rate alarm {fail_alarm!r} history {transitions!r} lacks a transition into ALARM"
    )
    fail_errors = sum(float(d["Sum"]) for d in _errors(cw, fail_fn, since))
    fail_invocations = sum(float(d["Sum"]) for d in _invocations(cw, fail_fn, since))
    assert fail_invocations > 0, f"AWS/Lambda Invocations for {fail_fn!r} sums to {fail_invocations!r}"
    rate = fail_errors / fail_invocations
    assert rate > 0.5, (
        f"real errors/invocations for {fail_fn!r} is {rate!r} ({fail_errors!r}/{fail_invocations!r}), "
        f"expected > 0.5 for the alarm to have genuinely breached"
    )

    # ---- the control: the healthy twin's rate never breached ----------------------------------
    final = _states()
    assert final.get(ok_alarm) == "OK", f"healthy twin's error-rate alarm ended {final.get(ok_alarm)!r}"
    assert set(ok_states) <= {"OK", "INSUFFICIENT_DATA"}, (
        f"healthy twin's error-rate alarm was observed in states {ok_states!r}"
    )
    ok_transitions = _transitions(cw, ok_alarm)
    assert all(t["new"] != "ALARM" for t in ok_transitions), (
        f"healthy twin's error-rate alarm history records an ALARM transition: {ok_transitions!r}"
    )




def _rate_metrics(fn_name: str) -> list[dict]:
    return [
        {
            "Id": "errors",
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/Lambda",
                    "MetricName": "Errors",
                    "Dimensions": [{"Name": "FunctionName", "Value": fn_name}],
                },
                "Period": 60,
                "Stat": "Sum",
            },
            "ReturnData": False,
        },
        {
            "Id": "invocations",
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/Lambda",
                    "MetricName": "Invocations",
                    "Dimensions": [{"Name": "FunctionName", "Value": fn_name}],
                },
                "Period": 60,
                "Stat": "Sum",
            },
            "ReturnData": False,
        },
        {"Id": "rate", "Expression": "errors / invocations", "Label": "ErrorRate", "ReturnData": True},
    ]


def _zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, src in files.items():
            zf.writestr(path, src)
    return buf.getvalue()


def _role(ctx) -> str:
    """An execution role with NO permissions: both functions only compute, so no log group leaks."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-cwmm-role-")[:64]
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


def _function(ctx, lam, role_arn: str, handler_src: str, suffix: str) -> str:
    name = ctx.unique_name(f"sim2real-xsvc-cwmm-{suffix}-")[:64]
    deadline = time.monotonic() + _ROLE_PROPAGATION_BUDGET_S
    while True:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="ruby3.3",
                Architectures=["x86_64"],
                Role=role_arn,
                Handler="handler.handler",
                Code={"ZipFile": _zip({"handler.rb": handler_src})},
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
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    return name


def _errors(cw, fn_name: str, since: datetime) -> list[dict]:
    return cw.get_metric_statistics(
        Namespace="AWS/Lambda",
        MetricName="Errors",
        Dimensions=[{"Name": "FunctionName", "Value": fn_name}],
        StartTime=since,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
        Period=60,
        Statistics=["Sum"],
    )["Datapoints"]


def _invocations(cw, fn_name: str, since: datetime) -> list[dict]:
    return cw.get_metric_statistics(
        Namespace="AWS/Lambda",
        MetricName="Invocations",
        Dimensions=[{"Name": "FunctionName", "Value": fn_name}],
        StartTime=since,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
        Period=60,
        Statistics=["Sum"],
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


def _poll(fetch, pred, budget_s: float, what: str):
    deadline = time.monotonic() + budget_s
    last = None
    while True:
        last = fetch()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {budget_s:.0f}s waiting for {what}; last={last!r}")
        time.sleep(10.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
