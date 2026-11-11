"""xsvc-cloudwatch-3-composite-alarm-and-rule-over-lambda-errors-and-sqs-depth-delivers-via-sns-to-sqs."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cloudwatch-3-composite-alarm-and-rule-over-lambda-errors-and-sqs-depth-delivers-via-sns-to-sqs"
GROUP = "alerting"
SERVICES = ["cloudwatch", "lambda", "sns", "sqs"]

_METRIC_BUDGET_S = 900.0
_DELIVERY_BUDGET_S = 180.0
_ROLE_PROPAGATION_BUDGET_S = 120.0

_HANDLER = '''
def handler(event, context):
    raise RuntimeError("sim2real deliberate failure")
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
    """A composite AND alarm over Lambda Errors and SQS depth stays OK and delivers nothing while
    only the SQS child is in ALARM, and once both are its SNS notification (composite name, OK ->
    ALARM) arrives in the sink queue."""
    cw = ctx.client("cloudwatch")
    lam = ctx.client("lambda")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    tags_ = [{"Key": "sim2real", "Value": "cloudwatch__lambda__sns__sqs"}]

    # The queue whose depth is a child metric: messages stay unconsumed so the depth stays > 0.
    depth_name = ctx.unique_name("sim2real-xsvc-cwcomp-depth-")[:80]
    depth_url = sqs.create_queue(QueueName=depth_name, tags={"sim2real": "cloudwatch__lambda__sns__sqs"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=depth_url))

    # The sink: SNS topic -> SQS queue, with a queue policy scoped to that topic.
    sink_name = ctx.unique_name("sim2real-xsvc-cwcomp-sink-")[:80]
    sink_url = sqs.create_queue(QueueName=sink_name, tags={"sim2real": "cloudwatch__lambda__sns__sqs"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=sink_url))
    sink_arn = sqs.get_queue_attributes(QueueUrl=sink_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-xsvc-cwcomp-"), Tags=tags_)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    sqs.set_queue_attributes(QueueUrl=sink_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage",
            "Resource": sink_arn, "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}}}]})})
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=sink_arn, ReturnSubscriptionArn=True)[
        "SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    role_arn = _role(ctx)
    fn = _function(ctx, lam, role_arn)

    lam_alarm = ctx.unique_name("sim2real-xsvc-cwcomp-lam-")
    cw.put_metric_alarm(
        AlarmName=lam_alarm, Namespace="AWS/Lambda", MetricName="Errors",
        Dimensions=[{"Name": "FunctionName", "Value": fn}], Statistic="Sum", Period=60,
        EvaluationPeriods=1, Threshold=0.0, ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="ignore", Tags=tags_,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[lam_alarm]))
    sqs_alarm = ctx.unique_name("sim2real-xsvc-cwcomp-sqs-")
    cw.put_metric_alarm(
        AlarmName=sqs_alarm, Namespace="AWS/SQS", MetricName="ApproximateNumberOfMessagesVisible",
        Dimensions=[{"Name": "QueueName", "Value": depth_name}], Statistic="Maximum", Period=60,
        EvaluationPeriods=1, Threshold=0.0, ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="ignore", Tags=tags_,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[sqs_alarm]))
    composite = ctx.unique_name("sim2real-xsvc-cwcomp-and-")
    rule = f'ALARM("{lam_alarm}") AND ALARM("{sqs_alarm}")'
    cw.put_composite_alarm(AlarmName=composite, AlarmRule=rule, AlarmActions=[topic_arn], Tags=tags_)
    # LIFO: the composite is deleted before the children it references.
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[composite]))

    # Child one: real queue depth.
    for i in range(3):
        sqs.send_message(QueueUrl=depth_url, MessageBody=f"sim2real depth {i}")
    _poll(lambda: _state(cw, sqs_alarm, "MetricAlarm"), lambda s: s == "ALARM", _METRIC_BUDGET_S,
          f"the SQS-depth child {sqs_alarm} to reach ALARM from AWS/SQS ApproximateNumberOfMessagesVisible")

    # Break one thing: only one child is in ALARM, so AND must be false and nothing is published.
    lam_state = _state(cw, lam_alarm, "MetricAlarm")
    assert lam_state != "ALARM", f"the Lambda child is {lam_state!r} although the function was never invoked"
    comp_state = _poll(lambda: _state(cw, composite, "CompositeAlarm"), lambda s: s != "INSUFFICIENT_DATA",
                       _DELIVERY_BUDGET_S, "the composite to evaluate its rule")
    assert comp_state == "OK", (
        f"composite {rule!r} is {comp_state!r} with only the SQS child in ALARM (Lambda child {lam_state!r})"
    )
    early = _receive(sqs, sink_url, wait_s=10)
    assert early == [], f"the sink received {early!r} while the composite's AND rule was false"
    assert _history(cw, composite) == [], "the composite recorded an Action while its rule was false"

    # Positive control: child two -- real Lambda errors -- makes the AND true.
    for _ in range(3):
        resp = lam.invoke(FunctionName=fn, Payload=b"{}")
        resp["Payload"].read()
        assert resp.get("FunctionError") == "Unhandled", f"the failing function returned {resp.get('FunctionError')!r}"
    _poll(lambda: _state(cw, lam_alarm, "MetricAlarm"), lambda s: s == "ALARM", _METRIC_BUDGET_S,
          f"the Lambda-errors child {lam_alarm} to reach ALARM from AWS/Lambda Errors")
    _poll(lambda: _state(cw, composite, "CompositeAlarm"), lambda s: s == "ALARM", _DELIVERY_BUDGET_S,
          "the composite to reach ALARM once both children are in ALARM")

    got = _poll(lambda: _receive(sqs, sink_url, wait_s=10), lambda m: len(m) >= 1, _DELIVERY_BUDGET_S,
                "the composite's SNS notification to arrive in the sink queue")
    envelope = json.loads(got[0]["Body"])
    assert envelope.get("Type") == "Notification" and envelope.get("TopicArn") == topic_arn, (
        f"sink message is not an SNS notification from {topic_arn!r}: {envelope!r}"
    )
    message = json.loads(envelope["Message"])
    assert message.get("AlarmName") == composite, f"notification names {message.get('AlarmName')!r}, not {composite!r}"
    assert message.get("NewStateValue") == "ALARM", f"notification NewStateValue {message.get('NewStateValue')!r}"
    assert message.get("OldStateValue") == "OK", f"notification OldStateValue {message.get('OldStateValue')!r}"
    actions = _history(cw, composite)
    assert any(json.loads(a["HistoryData"]).get("actionState") == "Succeeded" for a in actions), (
        f"the composite's Action history has no Succeeded item: {actions!r}"
    )


def _zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, src in files.items():
            zf.writestr(path, src)
    return buf.getvalue()


def _role(ctx) -> str:
    """An execution role with NO permissions at all: the function only throws, and a role that cannot
    write CloudWatch Logs means no /aws/lambda/<fn> log group is left behind."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-cwcomp-role-")[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__lambda__sns__sqs"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _function(ctx, lam, role_arn: str) -> str:
    name = ctx.unique_name("sim2real-xsvc-cwcomp-fn-")[:64]
    logs = ctx.client("logs")
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + _ROLE_PROPAGATION_BUDGET_S
    while True:
        try:
            lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="handler.handler",
                Code={"ZipFile": _zip({"handler.py": _HANDLER})}, Timeout=15, MemorySize=128,
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


def _state(cw, name: str, kind: str) -> str:
    resp = cw.describe_alarms(AlarmNames=[name], AlarmTypes=[kind])
    found = resp["MetricAlarms"] if kind == "MetricAlarm" else resp["CompositeAlarms"]
    assert len(found) == 1, f"describe_alarms({name!r}, {kind}) returned {len(found)} alarms"
    return found[0]["StateValue"]


def _history(cw, name: str) -> list:
    items = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
        AlarmName=name, HistoryItemType="Action", AlarmTypes=["CompositeAlarm"]
    ):
        items.extend(page["AlarmHistoryItems"])
    return items


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
