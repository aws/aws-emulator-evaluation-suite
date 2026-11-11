"""alias-resource-dimension-alarm-isolates-failing-alias."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alias-resource-dimension-alarm-isolates-failing-alias"
GROUP = "alerting"
SERVICES = ["cloudwatch", "lambda"]

_ROLE_PROPAGATION_BUDGET_S = 120.0
_METRIC_BUDGET_S = 300.0
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."

_OK_HANDLER = "def handler(event, context):\n    return {'ok': True}\n"
_FAIL_HANDLER = "def handler(event, context):\n    raise RuntimeError('sim2real deliberate failure')\n"


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
    """Two AWS/Lambda Errors alarms on the SAME function, scoped by the two-dimension
    FunctionName+Resource form to one alias each, diverge exactly with the alias invoked: the
    alias whose published version fails reaches ALARM while the other alias's alarm stays OK.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics.html
    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html
    """
    cw = ctx.client("cloudwatch")
    lam = ctx.client("lambda")

    role_arn = _role(ctx)
    fn, _ok_version, ok_alias, _fail_version, fail_alias = _function_with_two_aliases(ctx, lam, role_arn)

    ok_alarm = ctx.unique_name("sim2real-xsvc-cwares-ok-")
    cw.put_metric_alarm(
        AlarmName=ok_alarm,
        Namespace="AWS/Lambda",
        MetricName="Errors",
        Dimensions=[{"Name": "FunctionName", "Value": fn}, {"Name": "Resource", "Value": f"{fn}:{ok_alias}"}],
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=0.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__lambda"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[ok_alarm]))
    fail_alarm = ctx.unique_name("sim2real-xsvc-cwares-fail-")
    cw.put_metric_alarm(
        AlarmName=fail_alarm,
        Namespace="AWS/Lambda",
        MetricName="Errors",
        Dimensions=[{"Name": "FunctionName", "Value": fn}, {"Name": "Resource", "Value": f"{fn}:{fail_alias}"}],
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=0.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__lambda"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[fail_alarm]))

    ok_states: list[str] = []

    def _states() -> dict[str, str]:
        resp = cw.describe_alarms(AlarmNames=[ok_alarm, fail_alarm], AlarmTypes=["MetricAlarm"])
        got = {a["AlarmName"]: a["StateValue"] for a in resp["MetricAlarms"]}
        if ok_alarm in got:
            ok_states.append(got[ok_alarm])
        assert got.get(ok_alarm) != "ALARM", (
            f"the never-failing alias's alarm {ok_alarm!r} entered ALARM although alias "
            f"{ok_alias!r} never raised; states so far: {ok_states!r}"
        )
        return got

    # ---- invoke each alias by its qualifier: one succeeds, one fails --------------------------
    for _ in range(3):
        resp = lam.invoke(FunctionName=fn, Qualifier=ok_alias, Payload=b"{}")
        payload = json.loads(resp["Payload"].read())
        assert resp.get("FunctionError") is None, f"alias {ok_alias!r} raised: {payload!r}"
        assert payload == {"ok": True}, f"alias {ok_alias!r} returned {payload!r}"
    for _ in range(3):
        resp = lam.invoke(FunctionName=fn, Qualifier=fail_alias, Payload=b"{}")
        payload = resp["Payload"].read()
        assert resp.get("FunctionError") == "Unhandled", (
            f"alias {fail_alias!r} returned FunctionError={resp.get('FunctionError')!r}, payload={payload!r}"
        )

    _poll(
        _states,
        lambda s: s.get(ok_alarm) == "OK",
        _METRIC_BUDGET_S,
        f"alarm {ok_alarm!r} to settle into OK from real non-breaching Errors on alias {ok_alias!r}",
    )
    _poll(
        _states,
        lambda s: s.get(fail_alarm) == "ALARM",
        _METRIC_BUDGET_S,
        f"alarm {fail_alarm!r} to reach ALARM from real AWS/Lambda Errors on alias {fail_alias!r}",
    )

    breached = cw.describe_alarms(AlarmNames=[fail_alarm], AlarmTypes=["MetricAlarm"])["MetricAlarms"][0]
    breached_dims = {d["Name"]: d["Value"] for d in breached["Dimensions"]}
    assert breached_dims == {"FunctionName": fn, "Resource": f"{fn}:{fail_alias}"}, (
        f"the breached alarm's Dimensions are {breached_dims!r}, expected FunctionName={fn!r} "
        f"and Resource={fn}:{fail_alias!r}"
    )
    transitions = _transitions(cw, fail_alarm)
    assert any(t["new"] == "ALARM" and t["old"] in ("OK", "INSUFFICIENT_DATA") for t in transitions), (
        f"alarm {fail_alarm!r} history {transitions!r} lacks a transition into ALARM"
    )

    # ---- the control: the other alias's identically-shaped alarm never alarmed ----------------
    final = _states()
    assert final.get(ok_alarm) == "OK", f"alias {ok_alias!r}'s alarm ended {final.get(ok_alarm)!r}"
    assert set(ok_states) <= {"OK", "INSUFFICIENT_DATA"}, (
        f"alias {ok_alias!r}'s alarm was observed in states {ok_states!r}"
    )
    ok_transitions = _transitions(cw, ok_alarm)
    assert all(t["new"] != "ALARM" for t in ok_transitions), (
        f"alias {ok_alias!r}'s alarm history records an ALARM transition: {ok_transitions!r}"
    )


def _zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, src in files.items():
            zf.writestr(path, src)
    return buf.getvalue()


def _role(ctx) -> str:
    """An execution role with NO permissions: the function only computes, so no log group leaks."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-cwares-role-")[:64]
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


def _function_with_two_aliases(ctx, lam, role_arn: str):
    """One function, published as a succeeding v1 and a failing v2, each behind its own alias."""
    name = ctx.unique_name("sim2real-xsvc-cwares-fn-")[:64]
    deadline = time.monotonic() + _ROLE_PROPAGATION_BUDGET_S
    while True:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.13",
                Architectures=["arm64"],
                Role=role_arn,
                Handler="handler.handler",
                Code={"ZipFile": _zip({"handler.py": _OK_HANDLER})},
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

    ok_version = lam.publish_version(FunctionName=name)["Version"]
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    ok_alias = ctx.unique_name("sim2real-ok-")[:30]
    lam.create_alias(FunctionName=name, Name=ok_alias, FunctionVersion=ok_version)
    ctx.on_cleanup(lambda: lam.delete_alias(FunctionName=name, Name=ok_alias))

    lam.update_function_code(FunctionName=name, ZipFile=_zip({"handler.py": _FAIL_HANDLER}))
    lam.get_waiter("function_updated_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    fail_version = lam.publish_version(FunctionName=name)["Version"]
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    fail_alias = ctx.unique_name("sim2real-fail-")[:30]
    lam.create_alias(FunctionName=name, Name=fail_alias, FunctionVersion=fail_version)
    ctx.on_cleanup(lambda: lam.delete_alias(FunctionName=name, Name=fail_alias))

    return name, ok_version, ok_alias, fail_version, fail_alias


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
