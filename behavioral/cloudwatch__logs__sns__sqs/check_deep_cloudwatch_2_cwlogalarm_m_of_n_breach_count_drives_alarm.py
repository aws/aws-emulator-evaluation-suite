"""deep-cloudwatch-2-cwlogalarm-m-of-n-breach-count-drives-alarm."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "deep-cloudwatch-2-cwlogalarm-m-of-n-breach-count-drives-alarm"

GROUP = "alerting"

SERVICES = ["cloudwatch", "logs", "sns", "sqs"]

_BREACH_LINES = 7
_SUB_THRESHOLD_LINES = 2
_THRESHOLD = 3.0
_N = 2  # QueryResultsToEvaluate
_M = 1  # QueryResultsToAlarm
_QUERY = "fields @timestamp, @message | filter @message like /BREACH/"


# timing:real-time — schedule: 60 s
@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c2",
    "timing:real-time",
)
def run(ctx) -> None:
    """A log alarm's state follows its scheduled query's count(*) under M-of-N (ALARM at 7 >= 3,
    a 2-line control reaches OK on N results), and SNS -> SQS notifications name the execution.
    """
    cw = ctx.client("cloudwatch")
    logs = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    topic, queue = _topic_to_queue(ctx)
    query_role = _role(ctx, "sq", ["logs.amazonaws.com"], _QUERY_ACTIONS)
    line_role = _role(
        ctx, "alr", ["cloudwatch.amazonaws.com", "logs.amazonaws.com"], _LOG_LINE_ACTIONS
    )
    breach_group = _log_group_with_stream(ctx, "breach")
    control_group = _log_group_with_stream(ctx, "ctrl")
    # IAM propagation has no observable condition to poll; give the new roles time to be assumable.
    time.sleep(10)

    marker = ctx.unique_name("m")
    now_ms = int(time.time() * 1000)
    breach_events = [
        {"timestamp": now_ms + i, "message": f"BREACH {marker} line={i}"} for i in range(_BREACH_LINES)
    ] + [{"timestamp": now_ms + 100 + i, "message": f"calm {marker} noise={i}"} for i in range(3)]
    ctrl_events = [
        {"timestamp": now_ms + i, "message": f"BREACH {marker} ctrl={i}"}
        for i in range(_SUB_THRESHOLD_LINES)
    ] + [{"timestamp": now_ms + 100, "message": f"calm {marker} ctrl-noise"}]
    for group, events in ((breach_group, breach_events), (control_group, ctrl_events)):
        resp = logs.put_log_events(logGroupName=group, logStreamName="s", logEvents=events)
        assert not resp.get("rejectedLogEventsInfo"), (
            f"PutLogEvents rejected events in {group}: {resp.get('rejectedLogEventsInfo')!r}"
        )

    breach_alarm = _xname(ctx, "la-breach")
    control_alarm = _xname(ctx, "la-ctrl")
    for alarm, group in ((breach_alarm, breach_group), (control_alarm, control_group)):
        put = cw.put_log_alarm(
            AlarmName=alarm,
            AlarmDescription="sim2real log alarm evaluation probe",
            ScheduledQueryConfiguration={
                "QueryString": _QUERY,
                "LogGroupIdentifiers": [group],
                "ScheduledQueryRoleARN": query_role,
                "ScheduleConfiguration": {
                    "ScheduleExpression": "rate(1 minute)",
                    "StartTimeOffset": 300,
                    "EndTimeOffset": 0,
                },
                "AggregationExpression": "count(*)",
            },
            QueryResultsToEvaluate=_N,
            QueryResultsToAlarm=_M,
            Threshold=_THRESHOLD,
            ComparisonOperator="GreaterThanOrEqualToThreshold",
            AlarmActions=[topic],
            OKActions=[topic],
            ActionLogLineCount=5,
            ActionLogLineRoleArn=line_role,
            Tags=_xsvc_tags_kv(),
        )
        ctx.on_cleanup(lambda a=alarm: ctx.client("cloudwatch").delete_alarms(AlarmNames=[a]))
        assert put["ResponseMetadata"]["HTTPStatusCode"] == 200, put["ResponseMetadata"]

    # --- QueryARN is populated, and it names a real, AWS-managed Logs scheduled query.
    breach_desc = _log_alarm(cw, breach_alarm)
    sq_conf = breach_desc["ScheduledQueryConfiguration"]
    query_arn = sq_conf.get("QueryARN", "")
    assert query_arn.startswith(f"arn:aws:logs:{ctx.region}:{account}:scheduled-query:"), (
        f"DescribeAlarms must populate QueryARN with a Logs scheduled-query ARN, got {query_arn!r}"
    )
    # Notifications carry no log lines in practice, so only the configuration round-trip is asserted.
    assert breach_desc["ActionLogLineCount"] == 5, breach_desc.get("ActionLogLineCount")
    assert breach_desc["ActionLogLineRoleArn"] == line_role, breach_desc.get("ActionLogLineRoleArn")
    assert sq_conf["ScheduleConfiguration"] == {
        "ScheduleExpression": "rate(1 minute)",
        "StartTimeOffset": 300,
        "EndTimeOffset": 0,
    }, f"schedule did not round-trip: {sq_conf.get('ScheduleConfiguration')!r}"
    managed = logs.get_scheduled_query(identifier=query_arn)
    assert managed["scheduledQueryArn"] == query_arn, managed.get("scheduledQueryArn")
    assert managed["queryString"] == _QUERY, f"managed query string {managed.get('queryString')!r}"
    assert managed["logGroupIdentifiers"] == [breach_group], managed.get("logGroupIdentifiers")
    assert managed["scheduleExpression"] == "rate(1 minute)", managed.get("scheduleExpression")
    assert managed["executionRoleArn"] == query_role, managed.get("executionRoleArn")
    assert managed["scheduleType"] == "AWS_MANAGED", (
        f"the alarm's query must be service-managed, got scheduleType {managed.get('scheduleType')!r}"
    )
    control_query_arn = _log_alarm(cw, control_alarm)["ScheduledQueryConfiguration"].get("QueryARN")
    assert control_query_arn and control_query_arn != query_arn, (
        f"each log alarm owns its own scheduled query; got {control_query_arn!r} vs {query_arn!r}"
    )

    # --- The breach group: the evaluator computes count(*) = 7 and goes to ALARM after M=1 result.
    # EVALUATION_ERROR is not terminal: an evaluation can fail while the new query role
    # propagates, and a later scheduled evaluation then succeeds.
    breach = _poll_until(
        lambda: _log_alarm(cw, breach_alarm),
        lambda a: a["StateValue"] == "ALARM",
        timeout_s=300,
        interval_s=10.0,
        description=f"{breach_alarm} evaluating {_BREACH_LINES} BREACH lines to ALARM",
    )
    assert breach["StateValue"] == "ALARM", (
        f"{breach_alarm} must reach ALARM; got {breach['StateValue']!r} "
        f"EvaluationState={breach.get('EvaluationState')!r} reason={breach.get('StateReason')!r}"
    )
    assert "EvaluationState" not in breach, (
        f"a healthy evaluation carries no EvaluationState, got {breach.get('EvaluationState')!r}"
    )
    breach_data = json.loads(breach["StateReasonData"])
    assert breach_data["threshold"] == _THRESHOLD, breach_data
    assert breach_data["queryResultsToEvaluate"] == _N, breach_data
    assert breach_data["queryResultsToAlarm"] == _M, breach_data
    results = breach_data["results"]
    assert 1 <= len(results) <= _N, f"StateReasonData must hold 1..N results, got {results!r}"
    breaching = [
        r for r in results if r.get("status") == "COMPLETE" and r.get("value", -1.0) >= _THRESHOLD
    ]
    assert len(breaching) >= _M, f"ALARM requires >= M={_M} breaching results, got {results!r}"
    assert all(r["value"] == float(_BREACH_LINES) for r in breaching), (
        f"count(*) must equal the {_BREACH_LINES} BREACH lines published (the 3 'calm' lines "
        f"must be filtered out); results were {results!r}"
    )
    breach_exec_ids = {r["queryResultId"] for r in breaching}

    # --- The control group: count 2 < 3 -> OK, and OK needs N=2 non-breaching results.
    control = _poll_until(
        lambda: _log_alarm(cw, control_alarm),
        lambda a: a["StateValue"] in ("OK", "ALARM"),
        timeout_s=300,
        interval_s=10.0,
        description=f"{control_alarm} evaluating {_SUB_THRESHOLD_LINES} BREACH lines to OK",
    )
    assert control["StateValue"] == "OK", (
        f"a count below threshold must yield OK, got {control['StateValue']!r} "
        f"reason={control.get('StateReason')!r}"
    )
    control_results = json.loads(control["StateReasonData"])["results"]
    assert len(control_results) == _N, (
        f"INSUFFICIENT_DATA -> OK must rest on N={_N} results, got {control_results!r}"
    )
    assert all(
        r.get("status") == "COMPLETE" and r.get("value") == float(_SUB_THRESHOLD_LINES)
        for r in control_results
    ), f"each control result must be COMPLETE with count {_SUB_THRESHOLD_LINES}, got {control_results!r}"
    control_history = cw.describe_alarm_history(
        AlarmName=control_alarm, AlarmTypes=["LogAlarm"], HistoryItemType="StateUpdate"
    )["AlarmHistoryItems"]
    entered = [json.loads(h["HistoryData"])["newState"]["stateValue"] for h in control_history]
    assert "OK" in entered and "ALARM" not in entered, (
        f"the sub-threshold control must enter OK and never ALARM; history states {entered!r}"
    )

    # --- Both transitions are delivered SNS -> SQS, naming the query execution that decided them.
    seen: list[dict[str, Any]] = []
    alarm_note = _await_payload(
        ctx, queue, lambda p: p.get("AlarmName") == breach_alarm and p.get("NewStateValue") == "ALARM",
        seen, timeout_s=180, description=f"ALARM notification for {breach_alarm}",
    )
    assert alarm_note["OldStateValue"] == "INSUFFICIENT_DATA", alarm_note.get("OldStateValue")
    assert alarm_note["LogGroups"] == [breach_group], alarm_note.get("LogGroups")
    assert alarm_note["QueryString"] == _QUERY, alarm_note.get("QueryString")
    assert alarm_note["AggregationExpression"] == "count(*)", alarm_note.get("AggregationExpression")
    assert alarm_note["AlarmArn"] == breach["AlarmArn"], alarm_note.get("AlarmArn")
    assert alarm_note["QueryExecutionId"] in breach_exec_ids, (
        f"the notification must name the execution whose count crossed the threshold: "
        f"{alarm_note.get('QueryExecutionId')!r} not in {sorted(breach_exec_ids)!r}"
    )
    ok_note = _await_payload(
        ctx, queue, lambda p: p.get("AlarmName") == control_alarm and p.get("NewStateValue") == "OK",
        seen, timeout_s=180, description=f"OK notification for {control_alarm}",
    )
    assert ok_note["LogGroups"] == [control_group], ok_note.get("LogGroups")
    assert not any(
        p.get("AlarmName") == control_alarm and p.get("NewStateValue") == "ALARM" for p in seen
    ), f"no ALARM notification may exist for the sub-threshold control: {seen!r}"

    # --- The execution named in the notification is in the managed query's own history.
    history = logs.get_scheduled_query_history(
        identifier=query_arn,
        startTime=int(time.time()) - 900,
        endTime=int(time.time()) + 60,
    )["triggerHistory"]
    by_id = {h["queryId"]: h for h in history}
    assert alarm_note["QueryExecutionId"] in by_id, (
        f"QueryExecutionId {alarm_note['QueryExecutionId']!r} absent from the scheduled query's "
        f"trigger history {sorted(by_id)!r}"
    )
    assert by_id[alarm_note["QueryExecutionId"]]["executionStatus"] == "Complete", by_id


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"

_QUERY_ACTIONS = [
    "logs:StartQuery",
    "logs:StopQuery",
    "logs:GetQueryResults",
    "logs:DescribeLogGroups",
]

_LOG_LINE_ACTIONS = [
    "logs:GetQueryResults",
    "logs:GetLogEvents",
    "logs:FilterLogEvents",
    "logs:GetLogRecord",
]


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _log_alarm(cw, name: str) -> dict[str, Any]:
    found = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["LogAlarm"])["LogAlarms"]
    assert len(found) == 1, f"DescribeAlarms(LogAlarm) for {name!r} returned {found!r}"
    return found[0]


def _role(ctx, kind: str, principals: list[str], actions: list[str]) -> str:
    """An IAM role trusting `principals`, with an inline policy granting `actions` on *."""
    iam = ctx.client("iam")
    name = _xname(ctx, kind)[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": principals}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_xsvc_tags_kv()
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="sim2real-log-alarm",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}
        ),
    )
    ctx.on_cleanup(
        lambda: ctx.client("iam").delete_role_policy(RoleName=name, PolicyName="sim2real-log-alarm")
    )
    return arn


def _log_group_with_stream(ctx, kind: str) -> str:
    """A log group (1-day retention, tagged) with a stream named 's'. Returns the group name."""
    logs = ctx.client("logs")
    group = _xname(ctx, f"lg-{kind}")
    logs.create_log_group(logGroupName=group, tags=_xsvc_resource_tags())
    ctx.on_cleanup(lambda: ctx.client("logs").delete_log_group(logGroupName=group))
    logs.put_retention_policy(logGroupName=group, retentionInDays=1)
    logs.create_log_stream(logGroupName=group, logStreamName="s")
    return group


def _topic_to_queue(ctx) -> tuple[str, str]:
    """An SNS topic with an SQS queue subscribed (queue policy scoped to the topic)."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic = sns.create_topic(Name=_xname(ctx, "topic"), Tags=_xsvc_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: ctx.client("sns").delete_topic(TopicArn=topic))
    url = sqs.create_queue(QueueName=_xname(ctx, "q"), tags=_xsvc_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=url))
    qarn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": qarn,
                "Condition": {"ArnEquals": {"aws:SourceArn": topic}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    sub = sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=qarn)
    ctx.on_cleanup(lambda: ctx.client("sns").unsubscribe(SubscriptionArn=sub["SubscriptionArn"]))
    return topic, url


def _alarm_payload(raw: str) -> dict[str, Any] | None:
    """Parse one SQS body into the CloudWatch alarm notification dict, or None if it is not one."""
    try:
        envelope = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(envelope, dict) or envelope.get("Type") != "Notification":
        return None
    try:
        payload = json.loads(envelope["Message"])
    except (KeyError, json.JSONDecodeError, ValueError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def _await_payload(ctx, queue_url, predicate, seen, *, timeout_s=180.0, description="notification"):
    """Drain SQS (recording every alarm payload into `seen`) until one satisfies predicate."""
    sqs = ctx.client("sqs")
    for p in seen:
        if predicate(p):
            return p
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            payload = _alarm_payload(msg.get("Body", ""))
            if payload is not None:
                seen.append(payload)
        for p in seen:
            if predicate(p):
                return p
    raise AssertionError(
        f"{description} not delivered within {timeout_s}s. "
        f"Payloads seen: {[(p.get('AlarmName'), p.get('NewStateValue')) for p in seen]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
