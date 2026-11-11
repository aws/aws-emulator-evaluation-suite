"""cw-alarm-action-to-deleted-topic-is-recorded-as-failed-and-delivers-nothing."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cw-alarm-action-to-deleted-topic-is-recorded-as-failed-and-delivers-nothing"
GROUP = "telemetry-delivery"
SERVICES = ["cloudwatch", "sns", "sqs"]

_TOGGLES = 4


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """An alarm fanning out to a live and a deleted SNS topic delivers every transition only to the
    live one, and DescribeAlarmHistory records each dispatch to the deleted topic as Failed with
    error 'Topic does not exist' and no publishedMessage."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    cw = ctx.client("cloudwatch")

    live = _topic_with_queue(ctx, "live")
    doomed = _topic_with_queue(ctx, "doomed")

    # Barrier part 1: both paths are proven reachable before anything is broken.
    for path in (live, doomed):
        canary = f"sim2real-canary-{path['label']}"
        sns.publish(TopicArn=path["topic_arn"], Message=canary)
        got = _wait_for_messages(sqs, path["queue_url"], expected=1, timeout_s=90.0)
        payload = json.loads(got[0])
        assert payload["Message"] == canary, (
            f"the {path['label']} path did not carry its own canary: {payload!r}. Neither the "
            f"absence nor the delivery asserted later would mean anything"
        )

    alarm_name = ctx.unique_name("sim2real-depth-actalarm-")
    namespace = ctx.unique_name("Sim2RealDepthActionNs")
    both = [live["topic_arn"], doomed["topic_arn"]]
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="ActionMetric",
        Statistic="Maximum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="missing",
        ActionsEnabled=True,
        # BOTH lists, so every toggle in either direction is a fan-out to both targets.
        AlarmActions=both,
        OKActions=both,
        AlarmDescription="sim2real depth: one live and one deleted SNS action target",
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    described = _describe(cw, alarm_name)
    assert sorted(described["AlarmActions"]) == sorted(both), (
        f"AlarmActions read back as {described['AlarmActions']!r}, expected {sorted(both)!r}"
    )
    assert described["ActionsEnabled"] is True, (
        f"ActionsEnabled is {described['ActionsEnabled']!r}; nothing below would dispatch"
    )

    # Break exactly ONE thing.
    sns.delete_topic(TopicArn=doomed["topic_arn"])
    doomed["topic_deleted"] = True

    try:
        sns.get_topic_attributes(TopicArn=doomed["topic_arn"])
        deleted_code = None
    except ClientError as exc:
        deleted_code = exc.response.get("Error", {}).get("Code")
    assert deleted_code == "NotFound", (
        f"GetTopicAttributes on the deleted topic {doomed['topic_arn']!r} returned "
        f"{deleted_code!r}, expected NotFound -- the break this check relies on is not "
        f"actually in effect"
    )

    _drain(sqs, live["queue_url"])
    _drain(sqs, doomed["queue_url"])

    # Four alternating transitions; SetAlarmState only dispatches on a CHANGE of state.
    wanted = ["ALARM", "OK", "ALARM", "OK"]
    assert len(wanted) == _TOGGLES, f"{wanted!r}"
    delivered: list[dict] = []
    for i, state in enumerate(wanted):
        cw.set_alarm_state(
            AlarmName=alarm_name, StateValue=state, StateReason=f"sim2real-depth-toggle-{i}"
        )
        bodies = _wait_for_messages(sqs, live["queue_url"], expected=1, timeout_s=120.0)
        delivered.append(json.loads(json.loads(bodies[0])["Message"]))

    assert len(delivered) == _TOGGLES, (
        f"only {len(delivered)!r} of {_TOGGLES} control deliveries arrived on the live path, so the "
        f"barrier is not established and the doomed side's emptiness proves nothing"
    )
    first = delivered[0]
    assert first["AlarmName"] == alarm_name, f"{first!r}"
    assert first["NewStateValue"] == "ALARM", f"{first!r}"
    assert [d["NewStateValue"] for d in delivered] == wanted, (
        f"the live path received states {[d['NewStateValue'] for d in delivered]!r}, expected "
        f"{wanted!r} -- the dispatcher must fan out every transition, not only the first"
    )

    # Only after sustained live deliveries is the doomed side's emptiness a real absence.
    doomed_msgs = _drain(sqs, doomed["queue_url"], wait_s=20)
    assert doomed_msgs == [], (
        f"the queue behind the DELETED topic still received {len(doomed_msgs)} message(s): "
        f"{doomed_msgs!r}"
    )
    approx = sqs.get_queue_attributes(
        QueueUrl=doomed["queue_url"],
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    assert approx["ApproximateNumberOfMessages"] == "0", (
        f"the doomed queue reports {approx!r} messages after {_TOGGLES} fan-outs"
    )

    # The dispatch failure is asynchronous: no API call raises, CloudWatch records it in history.
    actions = _poll_until(
        lambda: _action_history(cw, alarm_name),
        lambda items: any(i.get("actionState") == "Failed" for i in items)
        and any(i.get("actionState") == "Succeeded" for i in items),
        timeout_s=120.0,
        interval_s=5.0,
        description=(
            "DescribeAlarmHistory(Action) recorded both a Succeeded and a Failed dispatch"
        ),
    )
    failed = [i for i in actions if i.get("actionState") == "Failed"]
    succeeded = [i for i in actions if i.get("actionState") == "Succeeded"]
    assert failed, f"no Failed action item was recorded; the items were {actions!r}"
    assert succeeded, f"no Succeeded action item was recorded; the items were {actions!r}"

    assert len(failed) == _TOGGLES, (
        f"{len(failed)!r} Failed dispatches were recorded for {_TOGGLES} fan-outs; the deleted "
        f"target must fail on EVERY attempt, not only the first: {failed!r}"
    )
    one_failed = failed[0]
    assert one_failed["notificationResource"] == doomed["topic_arn"], (
        f"the Failed dispatch names {one_failed.get('notificationResource')!r}, expected the "
        f"deleted topic {doomed['topic_arn']!r}: {one_failed!r}"
    )
    assert one_failed["error"] == "Topic does not exist", (
        f"the dispatcher recorded error {one_failed.get('error')!r}, expected the measured "
        f"'Topic does not exist': {one_failed!r}"
    )
    assert one_failed.get("publishedMessage") is None, (
        f"a Failed action still reported a publishedMessage, so the dispatcher believes it handed a "
        f"payload to a topic that does not exist: {one_failed!r}"
    )
    one_ok = succeeded[0]
    assert one_ok["notificationResource"] == live["topic_arn"], (
        f"the Succeeded dispatch names {one_ok.get('notificationResource')!r}, expected the live "
        f"topic {live['topic_arn']!r}: {one_ok!r}"
    )
    assert one_ok["error"] is None, (
        f"a Succeeded dispatch to the live topic also recorded an error: {one_ok!r}"
    )
    assert alarm_name in (one_ok.get("publishedMessage") or ""), (
        f"the Succeeded action's publishedMessage does not contain the alarm name {alarm_name!r}, "
        f"so the recorded payload is not the one this alarm produced: "
        f"{(one_ok.get('publishedMessage') or '')[:400]!r}"
    )
    assert {i["notificationResource"] for i in failed} == {doomed["topic_arn"]}, (
        f"a dispatch to the LIVE topic was also recorded as Failed: "
        f"{[i for i in failed if i['notificationResource'] != doomed['topic_arn']]!r}"
    )


_MANAGED_TAG_KEY = "sim2real:managed"
_TAG_PREFIX = "sim2real-depth"


def _resource_tags():
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _TAG_PREFIX}


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _topic_with_queue(ctx, label):
    """An SNS topic fanning out to its own SQS queue, with cleanup registered per create."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-depth-{label}-q-"), tags=_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    topic_arn = sns.create_topic(
        Name=ctx.unique_name(f"sim2real-depth-{label}-t-"), Tags=_tags_kv()
    )["TopicArn"]
    path = {"label": label, "queue_url": queue_url, "queue_arn": queue_arn,
            "topic_arn": topic_arn, "topic_deleted": False}
    # Swallowed by the runner if the topic was deliberately deleted mid-check; registered anyway so
    # the live topic is always torn down.
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
                        }
                    ],
                }
            )
        },
    )
    sub = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)
    ctx.on_cleanup(lambda arn=sub["SubscriptionArn"]: sns.unsubscribe(SubscriptionArn=arn))
    return path


def _wait_for_messages(sqs, queue_url, *, expected, timeout_s):
    """Receive exactly `expected` bodies, deleting each; FAIL on exhaustion."""
    out = []
    deadline = time.monotonic() + timeout_s
    while len(out) < expected:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            out.append(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if len(out) < expected and time.monotonic() >= deadline:
            raise AssertionError(
                f"expected {expected} message(s) on {queue_url.rsplit('/', 1)[-1]} within "
                f"{timeout_s}s, got {len(out)}: {out!r}"
            )
    return out


def _drain(sqs, queue_url, *, wait_s=5):
    """Long-poll the queue empty and return whatever was there."""
    out = []
    while True:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s
        )
        messages = resp.get("Messages", [])
        if not messages:
            return out
        for msg in messages:
            out.append(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])


def _describe(cw, alarm_name):
    for page in cw.get_paginator("describe_alarms").paginate(
        AlarmNames=[alarm_name], AlarmTypes=["MetricAlarm"]
    ):
        for alarm in page.get("MetricAlarms", []):
            if alarm["AlarmName"] == alarm_name:
                return alarm
    raise AssertionError(f"alarm {alarm_name!r} is not present in DescribeAlarms")


def _action_history(cw, alarm_name):
    """Every Action history item, parsed. Paginated -- a busy alarm writes many."""
    items = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
        AlarmName=alarm_name, HistoryItemType="Action", ScanBy="TimestampDescending"
    ):
        for item in page.get("AlarmHistoryItems", []):
            try:
                items.append(json.loads(item["HistoryData"]))
            except (ValueError, TypeError, KeyError):
                items.append({"unparsable": item.get("HistoryData")})
    return items


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); FAIL on exhaustion, never skip."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not happen within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
