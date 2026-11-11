"""executions-failed-metric-fires-its-alarm-and-notifies-while-the-succeeding-twin-alarm-stays-ok."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "executions-failed-metric-fires-its-alarm-and-notifies-while-the-succeeding-twin-alarm-stays-ok"
GROUP = "metrics-and-alarms"
SERVICES = ["cloudwatch", "stepfunctions"]

_N_FAILURES = 3
_ALARM_BUDGET_S = 600.0
_METRIC_BUDGET_S = 300.0
_EXECUTION_BUDGET_S = 120.0
_NOTIFY_BUDGET_S = 180.0
#: Ceiling on the twin alarm's first evaluation (one 60 s period plus evaluation lag).
_TWIN_EVAL_BUDGET_S = 180.0
#: The twin's absence window: one more 60 s evaluation period after the failing alarm fired.
_ABSENCE_HOLD_S = 60.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """Failing executions publish AWS/States ExecutionsFailed that drives an alarm to ALARM by
    evaluation and delivers its notification, while the alarm on a twin that only succeeds stays OK
    and records no action; the series count exactly the executions run.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/procedure-cw-metrics.html
    """
    sfn = ctx.client("stepfunctions")
    cw = ctx.client("cloudwatch")

    role_arn = _states_role(ctx)
    topic_arn, queue_url = _topic_to_queue(ctx)

    failing = _state_machine(ctx, sfn, role_arn, "failing-", _FAIL_DEFINITION)
    healthy = _state_machine(ctx, sfn, role_arn, "healthy-", _SUCCEED_DEFINITION)

    # ExecutionsFailed is a burst metric, not a level. Once the 3
    # failures are more than one Period old, the latest evaluation window has NO datapoint for it —
    # and TreatMissingData="notBreaching" reads that absence as "not breaching", so the alarm reverts
    # to OK on its own within a couple of minutes even though nothing "fixed" the failing machine.
    # The two alarms need DIFFERENT missing-data policies to each make their own claim true:
    #   - the failing machine's alarm uses "ignore" (hold the last evaluated state) so the real ALARM
    #     the burst caused LATCHES, which is what "still ALARM after the twin's hold window" asserts.
    #   - the twin's alarm keeps "notBreaching" so it settles at a definitive OK instead of parking in
    #     INSUFFICIENT_DATA forever.
    failing_alarm = _alarm_on_executions_failed(
        ctx, cw, failing, topic_arn, "fail-", treat_missing_data="ignore"
    )
    healthy_alarm = _alarm_on_executions_failed(
        ctx, cw, healthy, topic_arn, "ok-", treat_missing_data="notBreaching"
    )

    # ---- drive the real transitions ----------------------------------------------------------- #
    for i in range(_N_FAILURES):
        arn = sfn.start_execution(
            stateMachineArn=failing, input=json.dumps({"i": i})
        )["executionArn"]
        status = _poll_until(
            lambda a=arn: sfn.describe_execution(executionArn=a)["status"],
            lambda s: s in {"FAILED", "SUCCEEDED", "TIMED_OUT", "ABORTED"},
            timeout_s=_EXECUTION_BUDGET_S,
            interval_s=3.0,
            description=f"failing execution {i + 1} of {_N_FAILURES} reaching a terminal status",
        )
        assert status == "FAILED", (
            f"execution {i + 1} of {_N_FAILURES} on the failing state machine ended {status!r}, "
            f"expected 'FAILED'; the ExecutionsFailed total below is only attributable to real "
            f"failures"
        )
    # The twin runs the SAME number of executions in the SAME window, so its alarm staying OK cannot
    # be explained by the twin simply being idle.
    for i in range(_N_FAILURES):
        arn = sfn.start_execution(
            stateMachineArn=healthy, input=json.dumps({"i": i})
        )["executionArn"]
        status = _poll_until(
            lambda a=arn: sfn.describe_execution(executionArn=a)["status"],
            lambda s: s in {"FAILED", "SUCCEEDED", "TIMED_OUT", "ABORTED"},
            timeout_s=_EXECUTION_BUDGET_S,
            interval_s=3.0,
            description=f"healthy execution {i + 1} of {_N_FAILURES} reaching a terminal status",
        )
        assert status == "SUCCEEDED", (
            f"execution {i + 1} of {_N_FAILURES} on the healthy twin ended {status!r}, expected "
            f"'SUCCEEDED'; the twin must be busy and healthy, not idle"
        )

    # ---- the metric leg: the datapoints the alarm will read exist and are correctly split ------ #
    window_start = datetime.now(timezone.utc) - timedelta(minutes=20)

    def _sum(machine_arn: str, metric: str) -> float | None:
        dps = cw.get_metric_statistics(
            Namespace="AWS/States",
            MetricName=metric,
            Dimensions=[{"Name": "StateMachineArn", "Value": machine_arn}],
            StartTime=window_start,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
            Period=60,
            Statistics=["Sum"],
        )["Datapoints"]
        return float(sum(d["Sum"] for d in dps)) if dps else None

    # Polled until both sums reach the executions run; an over-count still fails the exact asserts.
    failed_sum, ok_sum = _poll_until(
        lambda: _pair(_sum(failing, "ExecutionsFailed"), _sum(healthy, "ExecutionsSucceeded")),
        lambda p: p is not None and min(p) >= float(_N_FAILURES),
        timeout_s=_METRIC_BUDGET_S,
        interval_s=10.0,
        description="AWS/States ExecutionsFailed (failing machine) and ExecutionsSucceeded (twin)",
    )
    assert failed_sum == float(_N_FAILURES), (
        f"AWS/States ExecutionsFailed Sum for the failing state machine settled at {failed_sum!r}, "
        f"expected {float(_N_FAILURES)} — the number of executions this check drove to FAILED"
    )
    assert ok_sum == float(_N_FAILURES), (
        f"AWS/States ExecutionsSucceeded Sum for the healthy twin settled at {ok_sum!r}, expected "
        f"{float(_N_FAILURES)}"
    )
    cross = _sum(failing, "ExecutionsSucceeded")
    assert cross in (None, 0.0), (
        f"AWS/States ExecutionsSucceeded for the FAILING state machine read {cross!r}; every one of "
        f"its {_N_FAILURES} executions ended FAILED, so a non-zero success count means the two "
        f"outcomes are not separated"
    )

    # ---- the alarm leg: a REAL datapoint drives the transition -------------------------------- #
    _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[failing_alarm])["MetricAlarms"][0]["StateValue"],
        lambda s: s == "ALARM",
        timeout_s=_ALARM_BUDGET_S,
        interval_s=5.0,
        description=(
            f"alarm {failing_alarm} on AWS/States ExecutionsFailed reaching ALARM from the "
            f"{_N_FAILURES} real failures (no SetAlarmState anywhere in this check)"
        ),
    )

    described = cw.describe_alarms(AlarmNames=[failing_alarm])["MetricAlarms"][0]
    assert described["Namespace"] == "AWS/States", (
        f"alarm {failing_alarm} reports Namespace {described['Namespace']!r}, expected 'AWS/States'"
    )
    assert described["MetricName"] == "ExecutionsFailed", (
        f"alarm {failing_alarm} reports MetricName {described['MetricName']!r}, expected "
        f"'ExecutionsFailed'"
    )
    assert {(d["Name"], d["Value"]) for d in described["Dimensions"]} == {
        ("StateMachineArn", failing)
    }, (
        f"alarm {failing_alarm} evaluates dimensions {described['Dimensions']!r}, expected exactly "
        f"StateMachineArn={failing} — an alarm on the undimensioned series would fire on any state "
        f"machine's failure in the account"
    )

    history = cw.describe_alarm_history(
        AlarmName=failing_alarm, HistoryItemType="StateUpdate", MaxRecords=20
    )["AlarmHistoryItems"]
    to_alarm = [h for h in history if "to ALARM" in h["HistorySummary"]]
    assert to_alarm, (
        f"alarm {failing_alarm} is in ALARM but DescribeAlarmHistory records no StateUpdate "
        f"transition into it; summaries were {[h['HistorySummary'] for h in history]!r}. An alarm "
        f"that reports a state it never transitioned into is reporting a constant"
    )
    reason = json.loads(to_alarm[0]["HistoryData"]).get("newState", {}).get("stateReason", "")
    assert "threshold" in reason.lower(), (
        f"the ALARM transition for {failing_alarm} gives stateReason {reason!r}; a datapoint-driven "
        f"transition must name the threshold it crossed, which is what distinguishes it from a "
        f"forced state"
    )

    # ---- the action really fired: terminal read at the SQS consumer ---------------------------- #
    payload = _poll_for_notification(
        ctx,
        queue_url,
        failing_alarm,
        timeout_s=_NOTIFY_BUDGET_S,
        description=f"the ALARM notification for {failing_alarm} arriving via SNS at the queue",
    )
    assert payload["NewStateValue"] == "ALARM", (
        f"the delivered notification for {failing_alarm} reports NewStateValue "
        f"{payload['NewStateValue']!r}, expected 'ALARM': {payload!r}"
    )
    assert payload["Trigger"]["Namespace"] == "AWS/States", (
        f"the notification's Trigger names namespace {payload['Trigger']['Namespace']!r}, expected "
        f"'AWS/States' — the notification must carry the SERVICE metric that caused it: {payload!r}"
    )
    assert payload["Trigger"]["MetricName"] == "ExecutionsFailed", (
        f"the notification's Trigger names metric {payload['Trigger']['MetricName']!r}, expected "
        f"'ExecutionsFailed': {payload!r}"
    )

    # ---- the twin stays OK, evaluated over the same periods as the failing alarm ------------- #
    # A new alarm reads INSUFFICIENT_DATA until its first evaluation; the twin's first verdict
    # must be OK (notBreaching over a series with no failure), then it holds.
    def _twin_state() -> str:
        return cw.describe_alarms(AlarmNames=[healthy_alarm])["MetricAlarms"][0]["StateValue"]

    first_verdict = _poll_until(
        _twin_state,
        lambda s: s != "INSUFFICIENT_DATA",
        timeout_s=_TWIN_EVAL_BUDGET_S,
        interval_s=5.0,
        description=f"the twin alarm {healthy_alarm} reaching its first evaluated state",
    )
    assert first_verdict == "OK", (
        f"the twin alarm {healthy_alarm} on a state machine with zero failed executions first "
        f"evaluated to {first_verdict!r}, expected 'OK'"
    )
    _assert_stays(
        lambda: cw.describe_alarms(AlarmNames=[healthy_alarm])["MetricAlarms"][0]["StateValue"],
        "OK",
        hold_s=_ABSENCE_HOLD_S,
        interval_s=10.0,
        description=(
            f"the twin alarm {healthy_alarm} on the healthy state machine's ExecutionsFailed stays "
            f"OK while the failing alarm is in ALARM"
        ),
    )
    twin_history = cw.describe_alarm_history(
        AlarmName=healthy_alarm, HistoryItemType="Action", MaxRecords=10
    )["AlarmHistoryItems"]
    assert twin_history == [], (
        f"the twin alarm {healthy_alarm} recorded {len(twin_history)} Action history items "
        f"{[h['HistorySummary'] for h in twin_history]!r}; a state machine with zero failed "
        f"executions must drive no action"
    )

    # ---- positive control, after the negative ------------------------------------------------- #
    still = cw.describe_alarms(AlarmNames=[failing_alarm])["MetricAlarms"][0]["StateValue"]
    assert still == "ALARM", (
        f"after the twin's hold window the failing alarm read {still!r}, expected it still in "
        f"ALARM — the twin's OK is only meaningful while the positive is still firing"
    )


_FAIL_DEFINITION = json.dumps(
    {
        "Comment": "Deterministically fails. No foreign artifact, so the failure is the state.",
        "StartAt": "Boom",
        "States": {
            "Boom": {
                "Type": "Fail",
                "Error": "Sim2RealDeliberateFailure",
                "Cause": "cloudwatch__stepfunctions ExecutionsFailed probe",
            }
        },
    }
)
_SUCCEED_DEFINITION = json.dumps(
    {
        "Comment": "Deterministically succeeds. The twin, busy in the same window.",
        "StartAt": "Fine",
        "States": {"Fine": {"Type": "Succeed"}},
    }
)


def _states_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-cwsfn-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "states.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__stepfunctions"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _state_machine(ctx, sfn, role_arn: str, label: str, definition: str) -> str:
    """Create a STANDARD state machine. Standard, not Express: Express executions do not publish the
    per-state-machine ExecutionsFailed series this check reads."""
    name = ctx.unique_name(f"sim2real-cwsfn-{label}")[:80]
    arn = _retry_on_role_propagation(
        lambda: sfn.create_state_machine(
            name=name,
            definition=definition,
            roleArn=role_arn,
            type="STANDARD",
            tags=[{"key": "sim2real", "value": "cloudwatch__stepfunctions"}],
        )["stateMachineArn"],
        description=f"CreateStateMachine {name} accepting the freshly created role {role_arn}",
    )
    ctx.on_cleanup(lambda: _delete_state_machine(sfn, arn))
    return arn


def _delete_state_machine(sfn, arn: str, timeout_s: float = 180.0) -> None:
    """Delete the state machine and wait until DescribeStateMachine no longer finds it (it reads
    DELETING meanwhile); only not-found means gone, every other error raises."""
    try:
        sfn.delete_state_machine(stateMachineArn=arn)
    except sfn.exceptions.StateMachineDoesNotExist:
        return
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = sfn.describe_state_machine(stateMachineArn=arn)["status"]
        except sfn.exceptions.StateMachineDoesNotExist:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"state machine {arn} still {status!r} {timeout_s}s after delete")
        time.sleep(3.0)


def _retry_on_role_propagation(call, *, description: str):
    """Retry ONLY the documented IAM-propagation refusal, bounded by a deadline that raises."""
    from botocore.exceptions import ClientError

    propagation_budget_s = 180.0
    deadline = time.monotonic() + propagation_budget_s
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return call()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in {"AccessDeniedException", "InvalidArn"}:
                raise
            last = exc
            time.sleep(10.0)
    raise AssertionError(
        f"{description} never succeeded within {propagation_budget_s}s; last refusal {last!r}"
    )


def _alarm_on_executions_failed(
    ctx, cw, machine_arn: str, topic_arn: str, label: str, *, treat_missing_data: str
) -> str:
    name = ctx.unique_name(f"sim2real-cwsfn-alarm-{label}")
    cw.put_metric_alarm(
        AlarmName=name,
        Namespace="AWS/States",
        MetricName="ExecutionsFailed",
        Dimensions=[{"Name": "StateMachineArn", "Value": machine_arn}],
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        TreatMissingData=treat_missing_data,
        ActionsEnabled=True,
        AlarmActions=[topic_arn],
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__stepfunctions"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))
    return name


def _topic_to_queue(ctx) -> tuple[str, str]:
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-cwsfn-topic-"),
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__stepfunctions"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cwsfn-q-"),
        tags={"sim2real": "cloudwatch__stepfunctions"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
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
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)[
        "SubscriptionArn"
    ]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))
    sns.set_topic_attributes(
        TopicArn=topic_arn,
        AttributeName="Policy",
        AttributeValue=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudwatch.amazonaws.com"},
                        "Action": "SNS:Publish",
                        "Resource": topic_arn,
                    }
                ],
            }
        ),
    )
    return topic_arn, queue_url


def _poll_for_notification(ctx, queue_url: str, alarm_name: str, *, timeout_s, description) -> dict:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    seen: list[str] = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            envelope = json.loads(m["Body"])
            payload = json.loads(envelope["Message"])
            seen.append(str(payload.get("AlarmName")))
            if payload.get("AlarmName") == alarm_name:
                return payload
    raise AssertionError(
        f"{description} did not happen within {timeout_s}s; alarm names seen on the queue were "
        f"{seen!r}"
    )


def _pair(a, b):
    return None if a is None or b is None else (a, b)


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last read {last!r}")


def _assert_stays(probe, expected, *, hold_s, interval_s=20.0, description="reading"):
    deadline = time.monotonic() + hold_s
    while True:
        got = probe()
        assert got == expected, (
            f"{description}: read {got!r}, expected it to stay {expected!r} for the whole {hold_s}s"
        )
        if time.monotonic() >= deadline:
            return
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
