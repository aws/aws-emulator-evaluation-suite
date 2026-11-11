"""throttles-alarm-breaches-on-reserved-zero-healthy-twin-ok."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "throttles-alarm-breaches-on-reserved-zero-healthy-twin-ok"
GROUP = "alerting"
SERVICES = ["cloudwatch", "lambda"]

_ROLE_PROPAGATION_BUDGET_S = 120.0
_METRIC_BUDGET_S = 300.0
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."

_HANDLER = "exports.handler = async (event) => ({ok: true});\n"


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
    """A CloudWatch alarm on AWS/Lambda Throttles (Sum, period 60) reaches ALARM only from genuine
    throttled invokes (ReservedConcurrentExecutions=0 refuses every call), while an identical
    alarm on a healthy twin, invoked the same number of times and never throttled, stays OK.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics.html
    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html
    """
    cw = ctx.client("cloudwatch")
    lam = ctx.client("lambda", config=Config(retries={"mode": "standard", "max_attempts": 5}))
    # Only the deliberately throttled invokes go without SDK retries: each is one request at the
    # service, and its TooManyRequestsException is the graded answer, not a transient to retry.
    lam_once = ctx.client("lambda", config=Config(retries={"total_max_attempts": 1}))

    role_arn = _role(ctx)
    throttled_fn = _function(ctx, lam, role_arn, "throttled", reserved_concurrency=0)
    healthy_fn = _function(ctx, lam, role_arn, "healthy", reserved_concurrency=None)

    throttle_alarm = ctx.unique_name("sim2real-xsvc-cwthr-throttle-")
    cw.put_metric_alarm(
        AlarmName=throttle_alarm,
        Namespace="AWS/Lambda",
        MetricName="Throttles",
        Dimensions=[{"Name": "FunctionName", "Value": throttled_fn}],
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=0.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__lambda"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[throttle_alarm]))
    healthy_alarm = ctx.unique_name("sim2real-xsvc-cwthr-healthy-")
    cw.put_metric_alarm(
        AlarmName=healthy_alarm,
        Namespace="AWS/Lambda",
        MetricName="Throttles",
        Dimensions=[{"Name": "FunctionName", "Value": healthy_fn}],
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=0.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__lambda"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[healthy_alarm]))

    healthy_states: list[str] = []

    def _states() -> dict[str, str]:
        resp = cw.describe_alarms(AlarmNames=[throttle_alarm, healthy_alarm], AlarmTypes=["MetricAlarm"])
        got = {a["AlarmName"]: a["StateValue"] for a in resp["MetricAlarms"]}
        if healthy_alarm in got:
            healthy_states.append(got[healthy_alarm])
        assert got.get(healthy_alarm) != "ALARM", (
            f"the healthy twin's alarm {healthy_alarm!r} entered ALARM although {healthy_fn!r} was "
            f"never throttled; states so far: {healthy_states!r}"
        )
        return got

    # ---- drive real throttles: every sync invoke of a zero-reserved-concurrency function -------
    for _ in range(3):
        try:
            lam_once.invoke(FunctionName=throttled_fn, Payload=b"{}")
            raise AssertionError(f"invoking {throttled_fn!r} with ReservedConcurrentExecutions=0 succeeded")
        except ClientError as exc:
            err = exc.response["Error"]
            assert err["Code"] == "TooManyRequestsException", (
                f"invoking the zero-reserved-concurrency function raised {err['Code']!r}, "
                f"expected TooManyRequestsException"
            )
            assert err["Message"] == "Rate Exceeded.", (
                f"TooManyRequestsException carried message {err['Message']!r}, expected 'Rate Exceeded.'"
            )

    for _ in range(3):
        resp = lam.invoke(FunctionName=healthy_fn, Payload=b"{}")
        payload = json.loads(resp["Payload"].read())
        assert resp.get("FunctionError") is None, f"the healthy twin raised: {payload!r}"
        assert payload == {"ok": True}, f"the healthy twin returned {payload!r}, expected {{'ok': True}}"

    _poll(
        _states,
        lambda s: s.get(healthy_alarm) == "OK",
        _METRIC_BUDGET_S,
        f"alarm {healthy_alarm!r} to settle into OK from real non-breaching Throttles on {healthy_fn!r}",
    )

    _poll(
        _states,
        lambda s: s.get(throttle_alarm) == "ALARM",
        _METRIC_BUDGET_S,
        f"alarm {throttle_alarm!r} to reach ALARM from real AWS/Lambda Throttles on {throttled_fn!r}",
    )
    transitions = _transitions(cw, throttle_alarm)
    assert any(t["new"] == "ALARM" and t["old"] in ("OK", "INSUFFICIENT_DATA") for t in transitions), (
        f"alarm {throttle_alarm!r} history {transitions!r} lacks a transition into ALARM"
    )
    alarm_detail = cw.describe_alarms(AlarmNames=[throttle_alarm], AlarmTypes=["MetricAlarm"])["MetricAlarms"][0]
    assert (alarm_detail["Namespace"], alarm_detail["MetricName"]) == ("AWS/Lambda", "Throttles"), (
        f"the breached alarm names {alarm_detail.get('Namespace')!r}/{alarm_detail.get('MetricName')!r}"
    )
    alarm_dims = {d["Name"]: d["Value"] for d in alarm_detail["Dimensions"]}
    assert alarm_dims == {"FunctionName": throttled_fn}, (
        f"the breached alarm's Dimensions are {alarm_dims!r}, expected FunctionName={throttled_fn!r}"
    )

    # ---- the control: the healthy twin never alarmed ------------------------------------------
    final = _states()
    assert final.get(healthy_alarm) == "OK", f"healthy twin's alarm ended {final.get(healthy_alarm)!r}"
    assert set(healthy_states) <= {"OK", "INSUFFICIENT_DATA"}, (
        f"healthy twin's alarm was observed in states {healthy_states!r}"
    )
    healthy_transitions = _transitions(cw, healthy_alarm)
    assert all(t["new"] != "ALARM" for t in healthy_transitions), (
        f"healthy twin's alarm history records an ALARM transition: {healthy_transitions!r}"
    )




def _zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, src in files.items():
            zf.writestr(path, src)
    return buf.getvalue()


def _role(ctx) -> str:
    """An execution role with NO permissions: both functions only compute, so no log group leaks."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-cwthr-role-")[:64]
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


def _function(ctx, lam, role_arn: str, suffix: str, *, reserved_concurrency) -> str:
    name = ctx.unique_name(f"sim2real-xsvc-cwthr-{suffix}-")[:64]
    deadline = time.monotonic() + _ROLE_PROPAGATION_BUDGET_S
    while True:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="nodejs22.x",
                Architectures=["arm64"],
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": _zip({"index.js": _HANDLER})},
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
    if reserved_concurrency is not None:
        lam.put_function_concurrency(FunctionName=name, ReservedConcurrentExecutions=reserved_concurrency)
    return name


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
