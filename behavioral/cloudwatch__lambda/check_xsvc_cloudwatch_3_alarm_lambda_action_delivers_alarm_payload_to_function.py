"""xsvc-cloudwatch-3-alarm-lambda-action-delivers-alarm-payload-to-function."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cloudwatch-3-alarm-lambda-action-delivers-alarm-payload-to-function"
GROUP = "alerting"
SERVICES = ["cloudwatch", "lambda"]

_DELIVERY_BUDGET_S = 240.0
_ROLE_PROPAGATION_BUDGET_S = 120.0

# The function records the alarm event it was handed as a custom metric whose DIMENSIONS are the
# payload's fields, so reading the datapoint back with an exact dimension set proves which payload
# arrived. It needs only cloudwatch:PutMetricData -- no Logs permission, so no log group is left.
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
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "axis:happy-path",
)
def run(ctx) -> None:
    """A metric alarm with a Lambda function as AlarmAction, forced into ALARM, invokes the function
    with the alarm's source, ARN, name, state, previous state and exact StateReason, and its history
    records a Succeeded action naming the function."""
    cw = ctx.client("cloudwatch")
    lam = ctx.client("lambda")
    account = ctx.client("sts").get_caller_identity()["Account"]
    namespace = ctx.unique_name("sim2real/xsvc-cwlam-")
    since = datetime.now(timezone.utc) - timedelta(minutes=5)

    role_arn = _role(ctx)
    fn_name, fn_arn = _function(ctx, lam, role_arn, namespace)
    _warm_up(lam, fn_name, cw, namespace, since)

    alarm = ctx.unique_name("sim2real-xsvc-cwlam-")
    cw.put_metric_alarm(
        AlarmName=alarm, Namespace=namespace, MetricName="Never", Statistic="Maximum",
        Period=60, EvaluationPeriods=1, Threshold=1.0, ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="ignore", AlarmActions=[fn_arn],
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__lambda"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm]))
    desc = _alarm(cw, alarm)
    alarm_arn = desc["AlarmArn"]
    assert desc["AlarmActions"] == [fn_arn], f"AlarmActions stored as {desc['AlarmActions']!r}"
    assert desc["StateValue"] == "INSUFFICIENT_DATA", f"new alarm starts in {desc['StateValue']!r}"

    lam.add_permission(
        FunctionName=fn_name, StatementId="sim2real-cw-alarm", Action="lambda:InvokeFunction",
        Principal="lambda.alarms.cloudwatch.amazonaws.com", SourceArn=alarm_arn, SourceAccount=account,
    )
    policy = json.loads(lam.get_policy(FunctionName=fn_name)["Policy"])
    assert [s["Principal"] for s in policy["Statement"]] == [{"Service": "lambda.alarms.cloudwatch.amazonaws.com"}], (
        f"resource policy statements: {policy['Statement']!r}"
    )

    reason = f"sim2real forced {ctx.unique_name('n-')}"
    cw.set_alarm_state(AlarmName=alarm, StateValue="ALARM", StateReason=reason)

    want = {
        "Source": "aws.cloudwatch", "AlarmArn": alarm_arn, "AlarmName": alarm,
        "State": "ALARM", "PreviousState": "INSUFFICIENT_DATA", "Reason": reason,
    }
    got = _poll(
        lambda: _count(cw, namespace, want, since),
        lambda n: n is not None and n >= 1,
        _DELIVERY_BUDGET_S,
        f"the function to record an alarm event with exactly {want!r}",
    )
    assert got >= 1.0, f"recorded alarm events {got!r}"

    hist = _poll(
        lambda: _history(cw, alarm),
        lambda h: any(json.loads(x["HistoryData"]).get("actionState") == "Succeeded" for x in h),
        _DELIVERY_BUDGET_S,
        "the alarm's Action history to record a Succeeded Lambda action",
    )
    assert any(fn_name in x["HistorySummary"] for x in hist), (
        f"no Action history item names the function {fn_name!r}: {[x['HistorySummary'] for x in hist]!r}"
    )


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
