"""obs-dynamodb-2-ccf-alarm-notifies-sqs-via-sns."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-dynamodb-2-ccf-alarm-notifies-sqs-via-sns"
GROUP = "metric-alarm-notification"
SERVICES = ["cloudwatch", "dynamodb"]

_REFUSALS = 12       # refused conditional PutItems -> ConditionalCheckFailedRequests Sum = 12
_THRESHOLD = 12.0    # Sum >= 12 over one 60 s period breaches: only the whole burst crosses it, so an
                     # evaluation that lands mid-burst sees a partial Sum and stays OK
_PERIOD_S = 60
#: Typical: OK ~25 s after PutMetricAlarm (notBreaching, no datapoints), ALARM ~2 min after the
#: burst, SNS->SQS delivery within seconds of the change; the bounds leave headroom over that.
_OK_TIMEOUT_S = 240
_ALARM_TIMEOUT_S = 420
_DELIVERY_TIMEOUT_S = 180


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _refusal_code(fn):
    """Error code of a call real AWS refuses. RAISES if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected the conditional write to be refused; it succeeded: {result!r}")


def _await_state(cw, alarm, want, timeout_s, interval_s=2, ctx=None):
    """Poll DescribeAlarms until the alarm's StateValue == want; return the alarm description."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        found = cw.describe_alarms(AlarmNames=[alarm])["MetricAlarms"]
        assert len(found) == 1, f"DescribeAlarms({alarm!r}) returned {len(found)} alarms"
        last = found[0]
        if last["StateValue"] == want:
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"alarm {alarm!r} to reach {want!r}: the run budget ended first; "
                                   f"not graded")
            raise AssertionError(
                f"alarm {alarm!r} never reached {want!r} within {timeout_s:.0f}s; last state "
                f"{last['StateValue']!r} reason {last.get('StateReason')!r}")
        time.sleep(interval_s)


def _state_updates(cw, alarm):
    """Every StateUpdate history item for the alarm, paginated, oldest first."""
    items, token = [], None
    while True:
        kw = {"AlarmName": alarm, "HistoryItemType": "StateUpdate", "ScanBy": "TimestampAscending"}
        if token:
            kw["NextToken"] = token
        page = cw.describe_alarm_history(**kw)
        items.extend(page["AlarmHistoryItems"])
        token = page.get("NextToken")
        if not token:
            return items


def _drain_for_alarm(sqs, queue_url, alarm, timeout_s, ctx=None):
    """Receive from the queue until an SNS envelope whose alarm payload names `alarm` arrives."""
    deadline = time.monotonic() + timeout_s
    seen = []
    while time.monotonic() < deadline:
        wait_s = max(1, min(20, int(deadline - time.monotonic())))
        msgs = sqs.receive_message(QueueUrl=queue_url, WaitTimeSeconds=wait_s,
                                   MaxNumberOfMessages=10).get("Messages", [])
        for m in msgs:
            envelope = json.loads(m["Body"])
            seen.append(envelope.get("Subject"))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            payload = json.loads(envelope["Message"])
            if payload.get("AlarmName") == alarm and payload.get("NewStateValue") == "ALARM":
                return envelope, payload
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"an ALARM notification naming {alarm!r} on the SQS queue: the run budget "
                           f"ended first; not graded")
    raise AssertionError(
        f"no ALARM notification naming {alarm!r} reached the SQS queue within {timeout_s:.0f}s; "
        f"subjects seen: {seen!r}")


def _ok_index_precedes(transitions):
    """True when the first transition INTO OK precedes the first OK -> ALARM."""
    into_ok = next((i for i, t in enumerate(transitions) if t[1] == "OK"), None)
    ok_alarm = transitions.index(("OK", "ALARM"))
    return into_ok is not None and into_ok < ok_alarm


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "concern:data-plane",
    "concern:eventing",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "axis:happy-path",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """Refused conditional PutItems drive a ConditionalCheckFailedRequests alarm OK -> ALARM with
    the exact breaching datapoint, and its SNS action reaches an SQS subscriber with a payload
    naming the alarm, its metric, table dimension and threshold.
    """
    ddb = ctx.client("dynamodb")
    cw = ctx.client("cloudwatch")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    table = ctx.unique_name("sim2real-xsvc-ccfal-")
    alarm = ctx.unique_name("sim2real-xsvc-ccfal-")
    topic_name = ctx.unique_name("sim2real-xsvc-ccfal-")
    queue_name = ctx.unique_name("sim2real-xsvc-ccfal-")

    ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))

    topic_arn = sns.create_topic(Name=topic_name,
                                 Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    queue_url = sqs.create_queue(QueueName=queue_name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    })})
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
                            ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    cw.put_metric_alarm(
        AlarmName=alarm, AlarmDescription=f"sim2real {CHECK}",
        Namespace="AWS/DynamoDB", MetricName="ConditionalCheckFailedRequests",
        Dimensions=[{"Name": "TableName", "Value": table}],
        Statistic="Sum", Period=_PERIOD_S, EvaluationPeriods=1, Threshold=_THRESHOLD,
        ComparisonOperator="GreaterThanOrEqualToThreshold", TreatMissingData="notBreaching",
        AlarmActions=[topic_arn],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm]))

    # --- the alarm must first settle at OK: no refusals yet, missing data is non-breaching ------
    ok = _await_state(cw, alarm, "OK", _budget_s(ctx, _OK_TIMEOUT_S), ctx=ctx)
    assert ok["Threshold"] == _THRESHOLD, f"alarm threshold read back as {ok['Threshold']!r}"

    # --- positive control: the conditional write SUCCEEDS where the key is absent -------------
    original = {"pk": {"S": "k"}, "v": {"S": "original"}}
    ddb.put_item(TableName=table, Item=original, ConditionExpression="attribute_not_exists(pk)")

    # Keep the burst inside one 60 s period so its Sum is exactly _REFUSALS: wait for the wall
    # clock to leave the last 15 s of a minute (the burst itself takes ~1-2 s).
    while datetime.now(timezone.utc).second > 45:
        time.sleep(1)
    burst_minute = datetime.now(timezone.utc).replace(second=0, microsecond=0)

    # --- break exactly one thing: the key now exists, so the same condition must fail ---------
    for i in range(_REFUSALS):
        code = _refusal_code(lambda i=i: ddb.put_item(
            TableName=table, Item={"pk": {"S": "k"}, "v": {"S": f"loser{i}"}},
            ConditionExpression="attribute_not_exists(pk)"))
        assert code == "ConditionalCheckFailedException", (
            f"refusal {i}: PutItem guarded by attribute_not_exists(pk) on an existing key raised "
            f"{code!r}, expected 'ConditionalCheckFailedException'")
    burst_end_minute = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    assert burst_end_minute == burst_minute, (
        f"the refusal burst straddled a period boundary ({burst_minute} -> {burst_end_minute}); "
        f"the burst is sized to land in one {_PERIOD_S}s period")

    # --- effect absent: every refused write left the stored item untouched --------------------
    stored = ddb.get_item(TableName=table, Key={"pk": {"S": "k"}}, ConsistentRead=True).get("Item")
    assert stored == original, f"after {_REFUSALS} refused writes the item is {stored!r}"

    # --- transition: OK -> ALARM, driven by exactly the refusals ------------------------------
    fired = _await_state(cw, alarm, "ALARM", _budget_s(ctx, _ALARM_TIMEOUT_S), ctx=ctx)
    reason = fired["StateReason"]
    assert f"threshold ({_THRESHOLD})" in reason and "[12.0 " in reason, (
        f"ALARM StateReason does not cite the 12.0 datapoint against threshold {_THRESHOLD}: "
        f"{reason!r}")
    reason_data = json.loads(fired["StateReasonData"])
    assert reason_data.get("threshold") == _THRESHOLD and reason_data.get("statistic") == "Sum", (
        f"StateReasonData does not describe a Sum against {_THRESHOLD}: {reason_data!r}")
    assert reason_data.get("recentDatapoints") == [float(_REFUSALS)], (
        f"the breaching datapoint should be exactly {_REFUSALS} refusals; "
        f"recentDatapoints={reason_data.get('recentDatapoints')!r}")

    history = _state_updates(cw, alarm)
    transitions = [(json.loads(h["HistoryData"])["oldState"]["stateValue"],
                    json.loads(h["HistoryData"])["newState"]["stateValue"]) for h in history]
    assert ("OK", "ALARM") in transitions, (
        f"StateUpdate history has no OK -> ALARM transition: {transitions!r}")
    to_alarm = [h for h in history
                if json.loads(h["HistoryData"])["newState"]["stateValue"] == "ALARM"]
    assert to_alarm[-1]["HistorySummary"] == "Alarm updated from OK to ALARM", (
        f"history summary was {to_alarm[-1]['HistorySummary']!r}")
    new_state = json.loads(to_alarm[-1]["HistoryData"])["newState"]
    assert f"threshold ({_THRESHOLD})" in new_state["stateReason"], (
        f"history newState reason does not cite the threshold: {new_state['stateReason']!r}")
    assert _ok_index_precedes(transitions), (
        f"OK -> ALARM must follow the initial settle into OK; history order was {transitions!r}")

    # --- delivery: CloudWatch -> SNS -> SQS, payload names the alarm and its trigger ----------
    envelope, payload = _drain_for_alarm(sqs, queue_url, alarm, _budget_s(ctx, _DELIVERY_TIMEOUT_S), ctx=ctx)
    assert envelope.get("Type") == "Notification" and envelope.get("TopicArn") == topic_arn, (
        f"SQS body is not an SNS Notification from our topic: "
        f"Type={envelope.get('Type')!r} TopicArn={envelope.get('TopicArn')!r}")
    assert envelope.get("Subject", "").startswith(f'ALARM: "{alarm}"'), (
        f"SNS subject does not name the alarm: {envelope.get('Subject')!r}")
    assert payload["OldStateValue"] == "OK", f"payload OldStateValue {payload['OldStateValue']!r}"
    trigger = payload.get("Trigger", {})
    assert (trigger.get("MetricName"), trigger.get("Namespace")) == (
        "ConditionalCheckFailedRequests", "AWS/DynamoDB"), f"payload Trigger {trigger!r}"
    dims = {d["name"]: d["value"] for d in trigger.get("Dimensions", [])}
    assert dims == {"TableName": table}, f"payload Trigger dimensions {dims!r}"
    assert trigger.get("Threshold") == _THRESHOLD, f"payload Trigger threshold {trigger!r}"
    assert payload["NewStateReason"] == reason, (
        f"notified reason {payload['NewStateReason']!r} != DescribeAlarms reason {reason!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
