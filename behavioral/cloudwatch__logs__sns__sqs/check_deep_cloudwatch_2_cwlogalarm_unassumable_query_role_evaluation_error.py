"""deep-cloudwatch-2-cwlogalarm-unassumable-query-role-evaluation-error."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "deep-cloudwatch-2-cwlogalarm-unassumable-query-role-evaluation-error"

GROUP = "alerting"

SERVICES = ["cloudwatch", "logs", "sns", "sqs"]

_BREACH_LINES = 7
_THRESHOLD = 3.0
_QUERY = "fields @timestamp, @message | filter @message like /BREACH/"


# timing:real-time — schedule: 60 s
@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """A log alarm whose ScheduledQueryRoleARN cannot be assumed is ACCEPTED at call time and
    fails ASYNCHRONOUSLY: EvaluationState=EVALUATION_ERROR, a FAILED query result, no ALARM and
    no notification -- while an identical alarm with an assumable role, over the same lines, ALARMs."""
    cw = ctx.client("cloudwatch")
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    topic, queue = _topic_to_queue(ctx)
    good_role, _ = _role(ctx, "good", ["logs.amazonaws.com"])
    bad_role, bad_role_name = _role(ctx, "bad", ["ec2.amazonaws.com"])
    group = _log_group_with_stream(ctx)
    # IAM propagation exposes no observable condition to poll; give the new roles time to be assumable.
    time.sleep(10)

    marker = ctx.unique_name("m")
    now_ms = int(time.time() * 1000)
    resp = logs.put_log_events(
        logGroupName=group,
        logStreamName="s",
        logEvents=[
            {"timestamp": now_ms + i, "message": f"BREACH {marker} line={i}"}
            for i in range(_BREACH_LINES)
        ],
    )
    assert not resp.get("rejectedLogEventsInfo"), resp.get("rejectedLogEventsInfo")

    good_alarm = _xname(ctx, "la-good")
    bad_alarm = _xname(ctx, "la-bad")

    def _put(alarm: str, role: str) -> dict[str, Any]:
        out = cw.put_log_alarm(
            AlarmName=alarm,
            ScheduledQueryConfiguration={
                "QueryString": _QUERY,
                "LogGroupIdentifiers": [group],
                "ScheduledQueryRoleARN": role,
                "ScheduleConfiguration": {
                    "ScheduleExpression": "rate(1 minute)",
                    "StartTimeOffset": 300,
                    "EndTimeOffset": 0,
                },
                "AggregationExpression": "count(*)",
            },
            QueryResultsToEvaluate=2,
            QueryResultsToAlarm=1,
            Threshold=_THRESHOLD,
            ComparisonOperator="GreaterThanOrEqualToThreshold",
            AlarmActions=[topic],
            Tags=_xsvc_tags_kv(),
        )
        ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[alarm]))
        return out

    bad_put = _put(bad_alarm, bad_role)
    good_put = _put(good_alarm, good_role)
    # Not a 400 at call time: the role is not assumed until the scheduled query runs.
    assert bad_put["ResponseMetadata"]["HTTPStatusCode"] == 200, bad_put["ResponseMetadata"]
    assert good_put["ResponseMetadata"]["HTTPStatusCode"] == 200, good_put["ResponseMetadata"]
    initial = _log_alarm(cw, bad_alarm)
    assert initial["StateValue"] == "INSUFFICIENT_DATA", initial["StateValue"]
    assert initial["ScheduledQueryConfiguration"]["ScheduledQueryRoleARN"] == bad_role, initial

    # --- The bad alarm's error surfaces asynchronously, on the evaluation, not the request.
    bad = _poll_until(
        lambda: _log_alarm(cw, bad_alarm),
        lambda a: a.get("EvaluationState") is not None or a["StateValue"] != "INSUFFICIENT_DATA",
        timeout_s=240,
        interval_s=10.0,
        description=f"{bad_alarm} reporting an evaluation outcome",
    )
    assert bad.get("EvaluationState") == "EVALUATION_ERROR", (
        f"an unassumable query role must yield EvaluationState EVALUATION_ERROR, got "
        f"{bad.get('EvaluationState')!r} state={bad['StateValue']!r} reason={bad.get('StateReason')!r}"
    )
    assert bad["StateValue"] == "INSUFFICIENT_DATA", bad["StateValue"]
    bad_results = json.loads(bad["StateReasonData"])["results"]
    assert bad_results and all(r.get("status") == "FAILED" for r in bad_results), (
        f"the failed evaluation must record FAILED query results, got {bad_results!r}"
    )
    assert not any("value" in r for r in bad_results), (
        f"a query that never ran cannot carry a computed value: {bad_results!r}"
    )

    # --- Differential barrier: the good alarm, same group/schedule, ALARMs and is DELIVERED.
    good = _poll_until(
        lambda: _log_alarm(cw, good_alarm),
        lambda a: a["StateValue"] == "ALARM" or a.get("EvaluationState") == "EVALUATION_ERROR",
        timeout_s=300,
        interval_s=10.0,
        description=f"positive control {good_alarm} reaching ALARM",
    )
    assert good["StateValue"] == "ALARM" and "EvaluationState" not in good, (
        f"positive control must ALARM cleanly; got {good['StateValue']!r} "
        f"EvaluationState={good.get('EvaluationState')!r} reason={good.get('StateReason')!r}"
    )
    good_values = [r.get("value") for r in json.loads(good["StateReasonData"])["results"]]
    assert float(_BREACH_LINES) in good_values, (
        f"positive control must compute count {_BREACH_LINES}, got {good_values!r}"
    )
    seen: list[dict[str, Any]] = []
    _await_payload(
        ctx, queue, lambda p: p.get("AlarmName") == good_alarm and p.get("NewStateValue") == "ALARM",
        seen, timeout_s=180, description=f"ALARM notification for control {good_alarm}",
    )
    still_bad = _log_alarm(cw, bad_alarm)
    assert still_bad["StateValue"] == "INSUFFICIENT_DATA", (
        f"behind the barrier the unassumable alarm must not have evaluated: {still_bad['StateValue']!r}"
    )
    assert still_bad.get("EvaluationState") == "EVALUATION_ERROR", still_bad.get("EvaluationState")
    assert not any(p.get("AlarmName") == bad_alarm for p in seen), (
        f"no notification may be sent for the unassumable alarm: {seen!r}"
    )

    # --- Close the loop: repair ONLY the trust policy; the same alarm must recover and ALARM.
    iam.update_assume_role_policy(RoleName=bad_role_name, PolicyDocument=json.dumps(_trust(["logs.amazonaws.com"])))
    # The first batch may age out of the 300 s window before the repaired role is in effect, so
    # publish a second batch of the same size; the window then holds one or both whole batches.
    again_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=group,
        logStreamName="s",
        logEvents=[
            {"timestamp": again_ms + i, "message": f"BREACH {marker} again={i}"}
            for i in range(_BREACH_LINES)
        ],
    )
    repaired = _poll_until(
        lambda: _log_alarm(cw, bad_alarm),
        lambda a: a["StateValue"] == "ALARM",
        timeout_s=300,
        interval_s=10.0,
        description=f"{bad_alarm} recovering after its role's trust policy was repaired",
    )
    assert "EvaluationState" not in repaired, (
        f"a recovered alarm must clear EvaluationState, got {repaired.get('EvaluationState')!r}"
    )
    repaired_values = [
        r["value"] for r in json.loads(repaired["StateReasonData"])["results"]
        if r.get("status") == "COMPLETE" and "value" in r
    ]
    assert any(v >= _THRESHOLD and v % _BREACH_LINES == 0 for v in repaired_values), (
        f"after repair the alarm must compute a whole number of {_BREACH_LINES}-line batches "
        f"at or above threshold, got {repaired_values!r}"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"

_QUERY_ACTIONS = [
    "logs:StartQuery",
    "logs:StopQuery",
    "logs:GetQueryResults",
    "logs:DescribeLogGroups",
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


def _trust(principals: list[str]) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": principals}, "Action": "sts:AssumeRole"}
        ],
    }


def _role(ctx, kind: str, principals: list[str]) -> tuple[str, str]:
    """A role trusting `principals` with the scheduled-query policy. Returns (arn, name)."""
    iam = ctx.client("iam")
    name = _xname(ctx, kind)[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(_trust(principals)), Tags=_xsvc_tags_kv()
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="sim2real-log-alarm",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow", "Action": _QUERY_ACTIONS, "Resource": "*"}]}
        ),
    )
    ctx.on_cleanup(
        lambda: ctx.client("iam").delete_role_policy(RoleName=name, PolicyName="sim2real-log-alarm")
    )
    return arn, name


def _log_group_with_stream(ctx) -> str:
    """A log group (1-day retention, tagged) with a stream named 's'. Returns the group name."""
    logs = ctx.client("logs")
    group = _xname(ctx, "lg")
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
