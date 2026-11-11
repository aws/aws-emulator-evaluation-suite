"""cloudwatch-alarm-missing-lambda-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cloudwatch-alarm-missing-lambda-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "lambda", "logs"]


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EventBridge rule on an alarm's state change targets a function that does not grant
    events.amazonaws.com: the ALARM transition never invokes it and dead-letters as NO_PERMISSIONS;
    after the grant, a fresh OK->ALARM transition through the same rule delivers the alarm's event."""
    alarm_name = ctx.unique_name("sim2real-alarm-")
    _create_dummy_metric_alarm(ctx, alarm_name)
    alarm_arn = _get_alarm_arn(ctx, alarm_name)

    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = {
        "source": ["aws.cloudwatch"],
        "detail-type": ["CloudWatch Alarm State Change"],
        "resources": [alarm_arn],
        "detail": {"state": {"value": ["ALARM"]}},
    }
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    # No retries and a dead-letter queue: the denied delivery fails once and lands on the queue,
    # so it can never reach the function after the grant below. The queue and its policy exist
    # before the function, so the policy has propagated by the time the first event fails.
    dlq_url, dlq_arn = _dlq_for_rule(ctx, rule_arn)

    role_arn = _create_lambda_role(ctx)
    function_name = _create_marker_function(ctx, role_arn, _LAMBDA_CODE_GENERIC)
    lam = ctx.client("lambda")
    function_arn = lam.get_function(FunctionName=function_name)["Configuration"]["FunctionArn"]

    resp = events.put_targets(Rule=rule_name, Targets=[{
        "Id": "1",
        "Arn": function_arn,
        "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
        "DeadLetterConfig": {"Arn": dlq_arn},
    }])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["1"]))
    assert resp["FailedEntryCount"] == 0, f"put_targets refused the target: {resp!r}"

    # Deliberately break exactly one thing: no lambda.add_permission grant for
    # events.amazonaws.com / this rule's ARN exists yet.
    cw = ctx.client("cloudwatch")
    since_ms = int(time.time() * 1000)

    # The dead-lettered denied event is the barrier: its one delivery attempt failed for want of
    # permission, before the grant exists. A fresh rule and target can miss the first state-change
    # events, so the denied OK->ALARM transition repeats until one dead-letters; every one of them
    # stays under the absence assertion below.
    dead = None
    deadline = _deadline(ctx, 300.0)
    while dead is None:
        assert time.monotonic() < deadline, (
            "no denied ALARM event dead-lettered within 300s of repeated transitions"
        )
        if _alarm_state(ctx, alarm_name) == "ALARM":
            cw.set_alarm_state(AlarmName=alarm_name, StateValue="OK", StateReason="reset before denied event")
            _wait_for_alarm_state(ctx, alarm_name, "OK")
        cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason=_DENIED_REASON)
        _wait_for_alarm_state(ctx, alarm_name, "ALARM")
        dead = _wait_for_dead_letter(ctx, dlq_url, _DENIED_REASON, timeout_s=45)
    attrs = {k: v.get("StringValue") for k, v in dead.get("MessageAttributes", {}).items()}
    assert attrs.get("RULE_ARN") == rule_arn, f"DLQ RULE_ARN {attrs.get('RULE_ARN')!r}"
    assert attrs.get("TARGET_ARN") == function_arn, f"DLQ TARGET_ARN {attrs.get('TARGET_ARN')!r}"
    assert attrs.get("ERROR_CODE") == "NO_PERMISSIONS", (
        f"DLQ ERROR_CODE {attrs.get('ERROR_CODE')!r}; all attributes {attrs!r}"
    )

    # Positive control: grant the permission, force a fresh OK->ALARM transition through the
    # SAME rule/target, and confirm delivery now happens.
    stmt_id = ctx.unique_name("sim2real-permit-")
    lam.add_permission(
        FunctionName=function_name,
        StatementId=stmt_id,
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )

    cw.set_alarm_state(AlarmName=alarm_name, StateValue="OK", StateReason="reset before positive control")
    _wait_for_alarm_state(ctx, alarm_name, "OK")
    since_ms2 = int(time.time() * 1000)
    cw.set_alarm_state(
        AlarmName=alarm_name, StateValue="ALARM", StateReason="positive control after granting permission"
    )
    _wait_for_alarm_state(ctx, alarm_name, "ALARM")
    markers = _wait_for_generic_marker(ctx, function_name, since_ms2, alarm_name, timeout_s=120)
    assert any(alarm_name in m for m in markers), f"expected alarm {alarm_name!r} in {markers!r}"

    # The denied event dead-lettered without retries, so no marker of it ever reaches the function.
    denied = [m for m in _markers(ctx, function_name, since_ms) if _DENIED_REASON in m]
    assert denied == [], (
        f"unexpected invocation without events.amazonaws.com permission: {denied!r}"
    )


#: The StateReason of the ALARM transition made while the function grants EventBridge nothing; the
#: delivered event carries it in detail.state.reason.
_DENIED_REASON = "negative check - no permission"


_LAMBDA_CODE_GENERIC = """
import json


def handler(event, context):
    print("SIM2REAL_MARKER:" + json.dumps(event))
    return {"ok": True}
"""


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    """Poll for an async cross-service effect."""
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


def _deadline(ctx, seconds: float) -> float:
    """A monotonic deadline of `seconds`, capped by the run's remaining budget."""
    left = ctx.time_left()
    return time.monotonic() + (seconds if left is None else min(seconds, left))


def _dlq_for_rule(ctx, rule_arn: str) -> tuple[str, str]:
    """A queue EventBridge may dead-letter into, scoped to this rule by aws:SourceArn."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-lgcwlam-dlq-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
        }],
    })})
    return url, arn


def _wait_for_dead_letter(ctx, url: str, reason: str, timeout_s: float) -> dict | None:
    """The first dead letter whose event carries detail.state.reason == reason, read and deleted;
    None if none arrives within timeout_s."""
    sqs = ctx.client("sqs")
    seen = []
    deadline = _deadline(ctx, timeout_s)
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5, MessageAttributeNames=["All"]
        )
        for m in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
            body = json.loads(m["Body"])
            if body.get("detail", {}).get("state", {}).get("reason") == reason:
                return m
            seen.append(m["Body"][:200])
    assert not seen, f"dead letters other than the denied event: {seen!r}"
    return None


def _make_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lgcwlam-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_marker_function(ctx, role_arn: str, code: str, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    function_name = ctx.unique_name("sim2real-lgcwlam-fn-")
    zip_bytes = _make_zip(code)

    def _try():
        try:
            ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
            return lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Publish=True,
                Tags={"sim2real": CHECK},
            )
        except lam.exceptions.InvalidParameterValueException as exc:
            if "role" in str(exc).lower():
                return None
            raise

    _poll_until(
        _try,
        lambda r: r is not None,
        timeout_s=60,
        interval_s=3.0,
        description="lambda create (role propagation)",
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    _poll_until(
        lambda: lam.get_function(FunctionName=function_name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=3.0,
        description=f"function {function_name} Active",
    )
    return function_name


def _create_dummy_metric_alarm(ctx, name: str) -> None:
    cw = ctx.client("cloudwatch")
    cw.put_metric_alarm(
        AlarmName=name,
        Namespace="Sim2RealBehavioral",
        MetricName="CheckMetric",
        Dimensions=[{"Name": "Check", "Value": name}],
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        # The metric is never published; 'ignore' keeps each forced state, so no evaluation adds a
        # transition of its own between the forced ones.
        TreatMissingData="ignore",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))


def _get_alarm_arn(ctx, name: str, composite: bool = False) -> str:
    cw = ctx.client("cloudwatch")
    key = "CompositeAlarms" if composite else "MetricAlarms"
    resp = cw.describe_alarms(AlarmNames=[name])
    return resp[key][0]["AlarmArn"]


def _alarm_state(ctx, name: str) -> str | None:
    alarms = ctx.client("cloudwatch").describe_alarms(AlarmNames=[name]).get("MetricAlarms", [])
    return alarms[0]["StateValue"] if alarms else None


def _wait_for_alarm_state(
    ctx, name: str, expected_state: str, composite: bool = False, timeout_s=60.0, interval_s=3.0
) -> str:
    cw = ctx.client("cloudwatch")
    key = "CompositeAlarms" if composite else "MetricAlarms"

    def _probe():
        alarms = cw.describe_alarms(AlarmNames=[name]).get(key, [])
        return alarms[0]["StateValue"] if alarms else None

    return _poll_until(
        _probe,
        lambda s: s == expected_state,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"alarm {name} state == {expected_state}",
    )


def _wait_for_generic_marker(
    ctx, function_name: str, since_ms: int, contains: str, timeout_s=120.0, interval_s=5.0
) -> list[str]:
    return _wait_for_effect(
        lambda: _markers(ctx, function_name, since_ms),
        lambda r: any(contains in m for m in r),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"marker containing {contains!r} delivered to {function_name}",
    )


def _markers(ctx, function_name: str, since_ms: int) -> list[str]:
    """Every SIM2REAL_MARKER line the function logged since since_ms; none before its log group
    exists."""
    logs = ctx.client("logs")
    out = []
    try:
        for page in logs.get_paginator("filter_log_events").paginate(
            logGroupName=f"/aws/lambda/{function_name}", startTime=since_ms
        ):
            out.extend(
                ev["message"] for ev in page.get("events", []) if "SIM2REAL_MARKER:" in ev["message"]
            )
    except logs.exceptions.ResourceNotFoundException:
        return []
    return out


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
