"""xsvc-cloudwatch-3-alarm-lambda-action-without-invoke-permission-denied."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cloudwatch-3-alarm-lambda-action-without-invoke-permission-denied"
GROUP = "alerting"
SERVICES = ["cloudwatch", "lambda"]

_DELIVERY_BUDGET_S = 240.0
_ROLE_PROPAGATION_BUDGET_S = 120.0
_REPAIR_BUDGET_S = 150.0

_HANDLER = '''
import os
import boto3

_cw = boto3.client("cloudwatch")


def handler(event, context):
    a = event.get("alarmData") or {}
    st = a.get("state") or {}
    prev = a.get("previousState") or {}
    dims = {
        "Source": event.get("source"),
        "AlarmArn": event.get("alarmArn"),
        "AlarmName": a.get("alarmName"),
        "State": st.get("value"),
        "PreviousState": prev.get("value"),
        "Reason": st.get("reason"),
    }
    _cw.put_metric_data(Namespace=os.environ["NS"], MetricData=[{
        "MetricName": "AlarmEvent", "Value": 1.0,
        "Dimensions": [{"Name": k, "Value": str(v)[:1024] or "-"} for k, v in dims.items()],
    }])
    return {"recorded": dims}
'''


@tags(
    "axis:negative-delivery",
    "cap:c7",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Lambda alarm action needs a resource-policy grant for the alarm's ARN: the ungranted alarm's
    action is Failed and never invokes the function, while a granted sibling alarm is delivered.
    Granting the denied alarm and re-driving it then delivers too.
    """
    cw = ctx.client("cloudwatch")
    lam = ctx.client("lambda")
    account = ctx.client("sts").get_caller_identity()["Account"]
    namespace = ctx.unique_name("sim2real/xsvc-cwlamneg-")
    since = datetime.now(timezone.utc) - timedelta(minutes=5)

    role_arn = _role(ctx)
    fn_name, fn_arn = _function(ctx, lam, role_arn, namespace)
    _warm_up(lam, fn_name, cw, namespace, since)

    alarms = {}
    for key in ("granted", "denied"):
        name = ctx.unique_name(f"sim2real-xsvc-cwlam-{key}-")
        cw.put_metric_alarm(
            AlarmName=name, Namespace=namespace, MetricName="Never", Statistic="Maximum",
            Period=60, EvaluationPeriods=1, Threshold=1.0, ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="ignore", AlarmActions=[fn_arn],
            Tags=[{"Key": "sim2real", "Value": "cloudwatch__lambda"}],
        )
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))
        alarms[key] = (name, _alarm(cw, name)["AlarmArn"])

    def grant(key):
        name, arn = alarms[key]
        lam.add_permission(
            FunctionName=fn_name, StatementId=f"sim2real-{key}", Action="lambda:InvokeFunction",
            Principal="lambda.alarms.cloudwatch.amazonaws.com", SourceArn=arn, SourceAccount=account,
        )

    grant("granted")
    stmts = json.loads(lam.get_policy(FunctionName=fn_name)["Policy"])["Statement"]
    assert [s["Sid"] for s in stmts] == ["sim2real-granted"], f"policy statements {stmts!r}"

    def event(key, state, prev, reason):
        name, arn = alarms[key]
        return {"Source": "aws.cloudwatch", "AlarmArn": arn, "AlarmName": name,
                "State": state, "PreviousState": prev, "Reason": reason}

    reasons = {k: f"sim2real forced {k} {ctx.unique_name('n-')}" for k in alarms}
    for key, (name, _) in alarms.items():
        cw.set_alarm_state(AlarmName=name, StateValue="ALARM", StateReason=reasons[key])

    # Positive control (and the barrier): the granted alarm's payload arrives.
    _poll(
        lambda: _count(cw, namespace, event("granted", "ALARM", "INSUFFICIENT_DATA", reasons["granted"]), since),
        lambda n: n is not None and n >= 1, _DELIVERY_BUDGET_S,
        "the granted alarm's payload to be recorded by the function",
    )
    _poll(
        lambda: _history(cw, alarms["granted"][0]),
        lambda h: any(json.loads(x["HistoryData"]).get("actionState") == "Succeeded" for x in h),
        _DELIVERY_BUDGET_S, "the granted alarm's Action history to record Succeeded",
    )

    # Effect absent, with the exact failure evidence on the denied alarm.
    failed = _poll(
        lambda: _history(cw, alarms["denied"][0]),
        lambda h: len(h) >= 1, _DELIVERY_BUDGET_S, "the denied alarm's Action history to record its attempt",
    )
    states = [json.loads(x["HistoryData"]).get("actionState") for x in failed]
    assert states == ["Failed"] * len(states), (
        f"the denied alarm's Action history shows actionState {states!r} with data "
        f"{[x['HistoryData'] for x in failed]!r}; without a resource-policy grant it must be Failed"
    )
    assert all(fn_name in x["HistorySummary"] for x in failed), (
        f"the Failed action items do not name {fn_name!r}: {[x['HistorySummary'] for x in failed]!r}"
    )
    denied_first = event("denied", "ALARM", "INSUFFICIENT_DATA", reasons["denied"])
    leaked = _count(cw, namespace, denied_first, since)
    assert leaked is None, (
        f"the function recorded {leaked!r} event(s) for the alarm that had NO invoke permission; Lambda "
        f"must deny an alarm whose ARN the resource policy does not grant"
    )

    # Repair the one broken thing: grant the denied alarm and re-drive it.
    grant("denied")
    dname = alarms["denied"][0]
    # A resource-policy grant exposes no condition to poll, so the first re-drive can still be
    # evaluated against the old policy. Bounded re-drive: each round is a fresh OK -> ALARM with
    # its own reason, retried only while that round's Action item says Failed.
    deadline = time.monotonic() + _REPAIR_BUDGET_S
    rounds = []
    while True:
        seen = len(_history(cw, dname))
        cw.set_alarm_state(AlarmName=dname, StateValue="OK", StateReason="sim2real reset")
        _poll(lambda: _alarm(cw, dname)["StateValue"], lambda s: s == "OK", 30.0, "the denied alarm to read OK")
        repaired = f"sim2real repaired {ctx.unique_name('n-')}"
        cw.set_alarm_state(AlarmName=dname, StateValue="ALARM", StateReason=repaired)
        items = _poll(lambda: _history(cw, dname), lambda h: len(h) > seen, 60.0,
                      "the re-driven alarm's Action history to record its attempt")
        outcome = json.loads(items[0]["HistoryData"]).get("actionState")
        rounds.append(outcome)
        if outcome == "Succeeded":
            break
        assert time.monotonic() < deadline, (
            f"the granted-after-the-fact alarm never succeeded; per-round action states {rounds!r}, last "
            f"{items[0]['HistoryData']!r}"
        )
        time.sleep(2)
    _poll(
        lambda: _count(cw, namespace, event("denied", "ALARM", "OK", repaired), since),
        lambda n: n is not None and n >= 1, _DELIVERY_BUDGET_S,
        f"the previously-denied alarm's payload to arrive once its grant exists (rounds {rounds!r})",
    )


# ===== helpers =====


def _zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, src in files.items():
            zf.writestr(path, src)
    return buf.getvalue()


def _role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-cwlam-role-")[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__lambda"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="put-metric",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "cloudwatch:PutMetricData", "Resource": "*"}]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="put-metric"))
    return arn


def _function(ctx, lam, role_arn: str, namespace: str):
    name = ctx.unique_name("sim2real-xsvc-cwlam-fn-")[:64]
    logs = ctx.client("logs")
    # Registered BEFORE the create so LIFO runs it AFTER delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + _ROLE_PROPAGATION_BUDGET_S
    while True:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="handler.handler",
                Code={"ZipFile": _zip({"handler.py": _HANDLER})}, Timeout=30, MemorySize=128,
                Environment={"Variables": {"NS": namespace}},
                Tags={"sim2real": "cloudwatch__lambda"},
            )["FunctionArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"CreateFunction {name} kept refusing the fresh role: {exc!r}") from exc
            time.sleep(5.0)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    return name, arn


def _warm_up(lam, fn_name: str, cw, namespace: str, since) -> None:
    """Invoke directly until the role's PutMetricData permission is effective (IAM propagation
    exposes no condition to poll), so the alarm's single async invoke is not lost to it."""
    event = {"source": "sim2real.warmup", "alarmArn": "warmup", "alarmData": {
        "alarmName": "warmup", "state": {"value": "WARMUP", "reason": "warmup"},
        "previousState": {"value": "WARMUP"}}}
    deadline = time.monotonic() + _ROLE_PROPAGATION_BUDGET_S
    while True:
        resp = lam.invoke(FunctionName=fn_name, Payload=json.dumps(event).encode())
        body = resp["Payload"].read()
        if resp.get("FunctionError") is None:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"warm-up invoke of {fn_name} kept failing: {body[:500]!r}")
        time.sleep(5.0)


def _alarm(cw, name: str) -> dict:
    found = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["MetricAlarm"])["MetricAlarms"]
    assert len(found) == 1, f"describe_alarms({name!r}) returned {len(found)} alarms"
    return found[0]


def _history(cw, name: str) -> list:
    items = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
        AlarmName=name, HistoryItemType="Action", AlarmTypes=["MetricAlarm"]
    ):
        items.extend(page["AlarmHistoryItems"])
    return items


def _count(cw, namespace: str, dims: dict, since):
    dps = cw.get_metric_statistics(
        Namespace=namespace, MetricName="AlarmEvent",
        Dimensions=[{"Name": k, "Value": v} for k, v in dims.items()],
        StartTime=since, EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
        Period=60, Statistics=["Sum"],
    )["Datapoints"]
    return float(sum(d["Sum"] for d in dps)) if dps else None


def _reap_log_group(logs, group: str) -> None:
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


def _poll(fetch, pred, budget_s: float, what: str):
    deadline = time.monotonic() + budget_s
    last = None
    while True:
        last = fetch()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {budget_s:.0f}s waiting for {what}; last={last!r}")
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
