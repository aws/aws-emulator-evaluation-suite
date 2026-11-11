"""lambda-errors-alarm-sns-sqs-delivery-healthy-twin-ok."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-errors-alarm-sns-sqs-delivery-healthy-twin-ok"
GROUP = "alerting"
SERVICES = ["cloudwatch", "lambda", "sns", "sqs"]

_ROLE_PROPAGATION_BUDGET_S = 120.0
_METRIC_BUDGET_S = 900.0
_DELIVERY_BUDGET_S = 300.0

_FAIL_HANDLER = '''
def handler(event, context):
    raise RuntimeError("sim2real deliberate failure")
'''
_OK_HANDLER = '''
def handler(event, context):
    return {"ok": True}
'''


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:negative-delivery",
    "cap:c4",
    "concern:e2e",
    "concern:eventing",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """An alarm on a failing function's AWS/Lambda Errors reaches ALARM and its SNS notification
    (alarm, transition, metric, dimension) lands in the queue, while a healthy twin's identical
    alarm, with live Errors datapoints of 0, stays OK and delivers nothing."""
    cw = ctx.client("cloudwatch")
    lam = ctx.client("lambda")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    sim2real_tag = [{"Key": "sim2real", "Value": "cloudwatch__lambda__sns__sqs"}]

    # ---- SNS topic -> SQS queue, shared by both alarms ------------------------------------- #
    sink_name = ctx.unique_name("sim2real-xsvc-cwlam-sink-")[:80]
    sink_url = sqs.create_queue(QueueName=sink_name, tags={"sim2real": "cloudwatch__lambda__sns__sqs"})[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=sink_url))
    sink_arn = sqs.get_queue_attributes(QueueUrl=sink_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-xsvc-cwlam-"), Tags=sim2real_tag)[
        "TopicArn"
    ]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    sqs.set_queue_attributes(
        QueueUrl=sink_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": sink_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
                        }
                    ],
                }
            )
        },
    )
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=sink_arn, ReturnSubscriptionArn=True)[
        "SubscriptionArn"
    ]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    # ---- one no-permission role, two functions ---------------------------------------------- #
    role_arn = _role(ctx)
    fail_fn = _function(ctx, lam, role_arn, _FAIL_HANDLER, "fail")
    ok_fn = _function(ctx, lam, role_arn, _OK_HANDLER, "ok")

    # ---- two identical alarms, one per function --------------------------------------------- #
    fail_alarm = ctx.unique_name("sim2real-xsvc-cwlam-fail-")
    cw.put_metric_alarm(
        AlarmName=fail_alarm,
        Namespace="AWS/Lambda",
        MetricName="Errors",
        Dimensions=[{"Name": "FunctionName", "Value": fail_fn}],
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=0.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        ActionsEnabled=True,
        AlarmActions=[topic_arn],
        Tags=sim2real_tag,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[fail_alarm]))
    ok_alarm = ctx.unique_name("sim2real-xsvc-cwlam-ok-")
    cw.put_metric_alarm(
        AlarmName=ok_alarm,
        Namespace="AWS/Lambda",
        MetricName="Errors",
        Dimensions=[{"Name": "FunctionName", "Value": ok_fn}],
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=0.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        ActionsEnabled=True,
        AlarmActions=[topic_arn],
        Tags=sim2real_tag,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[ok_alarm]))

    ok_states: list[str] = []

    def _states() -> dict[str, str]:
        resp = cw.describe_alarms(AlarmNames=[fail_alarm, ok_alarm], AlarmTypes=["MetricAlarm"])
        got = {a["AlarmName"]: a["StateValue"] for a in resp["MetricAlarms"]}
        if ok_alarm in got:  # DescribeAlarms can omit a just-created alarm; only real states count
            ok_states.append(got[ok_alarm])
        assert got.get(ok_alarm) != "ALARM", (
            f"the healthy twin's alarm {ok_alarm!r} entered ALARM although {ok_fn!r} never raised; "
            f"states observed so far: {ok_states!r}"
        )
        return got

    # ---- drive real invokes: the failing function fails, the healthy twin never does --------- #
    for _ in range(3):
        resp = lam.invoke(FunctionName=fail_fn, Payload=b"{}")
        payload = resp["Payload"].read()
        assert resp.get("FunctionError") == "Unhandled", (
            f"the failing function returned FunctionError={resp.get('FunctionError')!r}, "
            f"payload={payload!r}"
        )
    for _ in range(3):
        resp = lam.invoke(FunctionName=ok_fn, Payload=b"{}")
        payload = json.loads(resp["Payload"].read())
        assert resp.get("FunctionError") is None, f"the healthy twin raised: {payload!r}"
        assert payload == {"ok": True}, f"the healthy twin returned {payload!r}, expected {{'ok': True}}"

    # The healthy twin's Errors series is genuinely live (real Sum 0 datapoints), so its later
    # silence is not a channel that never carried telemetry.
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    _poll(
        lambda: _stats(cw, ok_fn, since),
        lambda dps: bool(dps),
        _METRIC_BUDGET_S,
        f"a real AWS/Lambda Errors datapoint under FunctionName={ok_fn!r}",
    )
    ok_errors = sum(float(d["Sum"]) for d in _stats(cw, ok_fn, since))
    assert ok_errors == 0.0, f"AWS/Lambda Errors for the healthy twin {ok_fn!r} sums to {ok_errors!r}"

    # The healthy twin's own alarm settles out of INSUFFICIENT_DATA into OK on its own evaluation
    # clock once it has seen a non-breaching datapoint -- never into ALARM, which _states() checks
    # on every call.
    _poll(
        _states,
        lambda s: s.get(ok_alarm) == "OK",
        _METRIC_BUDGET_S,
        f"alarm {ok_alarm!r} to settle into OK from real non-breaching AWS/Lambda Errors on {ok_fn!r}",
    )

    # ---- the failing function's alarm reaches ALARM from real Errors datapoints -------------- #
    _poll(
        _states,
        lambda s: s.get(fail_alarm) == "ALARM",
        _METRIC_BUDGET_S,
        f"alarm {fail_alarm!r} to reach ALARM from real AWS/Lambda Errors on {fail_fn!r}",
    )
    fail_transitions = _transitions(cw, fail_alarm)
    assert any(t["new"] == "ALARM" and t["old"] in ("OK", "INSUFFICIENT_DATA") for t in fail_transitions), (
        f"alarm {fail_alarm!r} history {fail_transitions!r} lacks a transition into ALARM"
    )

    # ---- its notification arrives in the shared queue within the declared budget ------------- #
    notifications: list[dict] = []

    def _drain() -> list[dict]:
        for msg in _receive(sqs, sink_url, wait_s=10):
            envelope = json.loads(msg["Body"])
            assert envelope.get("Type") == "Notification", f"not an SNS envelope: {envelope!r}"
            assert envelope.get("TopicArn") == topic_arn, (
                f"envelope TopicArn {envelope.get('TopicArn')!r}, expected {topic_arn!r}"
            )
            notifications.append(json.loads(envelope["Message"]))
        return notifications

    _poll(
        _drain,
        lambda n: any(p.get("AlarmName") == fail_alarm for p in n),
        _DELIVERY_BUDGET_S,
        f"the ALARM notification for {fail_alarm!r} to arrive in the SNS-subscribed queue",
    )
    message = next(p for p in notifications if p.get("AlarmName") == fail_alarm)
    assert message["NewStateValue"] == "ALARM" and message["OldStateValue"] in ("OK", "INSUFFICIENT_DATA"), (
        f"notification states {message.get('OldStateValue')!r} -> {message.get('NewStateValue')!r}, "
        f"expected a transition into ALARM: {message!r}"
    )
    trigger = message["Trigger"]
    assert (trigger["Namespace"], trigger["MetricName"]) == ("AWS/Lambda", "Errors"), (
        f"notification Trigger names {trigger.get('Namespace')!r}/{trigger.get('MetricName')!r}"
    )
    trig_dims = {d["name"]: d["value"] for d in trigger["Dimensions"]}
    assert trig_dims == {"FunctionName": fail_fn}, (
        f"notification Trigger dimensions {trig_dims!r}, expected FunctionName={fail_fn!r}"
    )

    # ---- the control: the healthy twin never alarmed and never delivered anything ------------ #
    final = _states()
    assert final.get(ok_alarm) == "OK", f"healthy twin's alarm {ok_alarm!r} ended {final.get(ok_alarm)!r}"
    assert set(ok_states) <= {"OK", "INSUFFICIENT_DATA"}, (
        f"healthy twin's alarm was observed in states {ok_states!r}"
    )
    ok_transitions = _transitions(cw, ok_alarm)
    assert all(t["new"] != "ALARM" for t in ok_transitions), (
        f"healthy twin's alarm {ok_alarm!r} history records an ALARM transition: {ok_transitions!r}"
    )
    stray = [p for p in notifications if p.get("AlarmName") != fail_alarm]
    assert stray == [], f"the queue delivered notifications for other alarms: {stray!r}"


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
    name = ctx.unique_name("sim2real-xsvc-cwlam-role-")[:64]
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
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__lambda__sns__sqs"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _function(ctx, lam, role_arn: str, handler_src: str, suffix: str) -> str:
    name = ctx.unique_name(f"sim2real-xsvc-cwlam-{suffix}-")[:64]
    deadline = time.monotonic() + _ROLE_PROPAGATION_BUDGET_S
    while True:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="handler.handler",
                Code={"ZipFile": _zip({"handler.py": handler_src})},
                Timeout=15,
                MemorySize=128,
                Tags={"sim2real": "cloudwatch__lambda__sns__sqs"},
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"CreateFunction {name} kept refusing the fresh role: {exc!r}") from exc
            time.sleep(5.0)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    return name


def _stats(cw, fn_name: str, since: datetime) -> list[dict]:
    return cw.get_metric_statistics(
        Namespace="AWS/Lambda",
        MetricName="Errors",
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


def _receive(sqs, url: str, wait_s: int) -> list:
    msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s).get("Messages", [])
    for m in msgs:
        sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return msgs


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
