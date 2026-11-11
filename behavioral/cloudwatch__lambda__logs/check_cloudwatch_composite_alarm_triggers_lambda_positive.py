"""cloudwatch-composite-alarm-triggers-lambda-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cloudwatch-composite-alarm-triggers-lambda-positive"
GROUP = "event-propagation"
SERVICES = ["cloudwatch", "lambda", "logs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A composite alarm entering ALARM invokes the function behind an EventBridge alarm
    state-change rule with an event naming the composite alarm and carrying its alarmRule."""
    role_arn = _create_lambda_role(ctx)
    function_name = _create_marker_function(ctx, role_arn, _LAMBDA_CODE_GENERIC)
    function_arn = ctx.client("lambda").get_function(FunctionName=function_name)["Configuration"]["FunctionArn"]

    cw = ctx.client("cloudwatch")
    child1 = ctx.unique_name("sim2real-childalarm1-")
    child2 = ctx.unique_name("sim2real-childalarm2-")
    _create_dummy_metric_alarm(ctx, child1)
    _create_dummy_metric_alarm(ctx, child2)

    composite_name = ctx.unique_name("sim2real-composite-")
    cw.put_composite_alarm(
        AlarmName=composite_name,
        AlarmRule=f'ALARM("{child1}") OR ALARM("{child2}")',
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[composite_name]))
    composite_arn = _get_alarm_arn(ctx, composite_name, composite=True)

    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = {
        "source": ["aws.cloudwatch"],
        "detail-type": ["CloudWatch Alarm State Change"],
        "resources": [composite_arn],
        "detail": {"state": {"value": ["ALARM"]}},
    }
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    stmt_id = ctx.unique_name("sim2real-permit-")
    ctx.client("lambda").add_permission(
        FunctionName=function_name,
        StatementId=stmt_id,
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )

    events.put_targets(Rule=rule_name, Targets=[{"Id": "1", "Arn": function_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["1"]))

    since_ms = int(time.time() * 1000)

    # Drive the transition through a real child-alarm state change (rather than forcing the
    # composite alarm's own state), since a manually forced composite state can be immediately
    # superseded by CloudWatch's continuous rule re-evaluation against the children's real
    # states before EventBridge delivery completes. Setting child1 to ALARM makes the
    # composite's "ALARM(child1) OR ALARM(child2)" rule genuinely evaluate to ALARM.
    #
    # SetAlarmState's override is transient: with no metric data behind child1, CloudWatch's
    # evaluation reverts it to INSUFFICIENT_DATA about one period (~60s) later, flipping the
    # composite back to OK, so child1's ALARM is re-asserted on every poll iteration below.
    def _keep_child1_alarmed():
        cw.set_alarm_state(
            AlarmName=child1, StateValue="ALARM", StateReason="sim2real behavioral check"
        )

    _keep_child1_alarmed()
    _wait_for_alarm_state(
        ctx, composite_name, "ALARM", composite=True, timeout_s=90.0, before=_keep_child1_alarmed
    )

    markers = _wait_for_generic_marker(
        ctx, function_name, since_ms, composite_name, timeout_s=120, before=_keep_child1_alarmed
    )
    matching = [m for m in markers if composite_name in m]
    assert matching, f"expected {composite_name!r} in {markers!r}"
    assert any('"alarmRule"' in m for m in matching), (
        f"expected the delivered event's configuration to include the composite alarmRule: {matching!r}"
    )


_LAMBDA_CODE_GENERIC = """
import json


def handler(event, context):
    print("SIM2REAL_MARKER:" + json.dumps(event))
    return {"ok": True}
"""


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition", before=None
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout).

    ``before``, if given, runs at the top of every iteration -- ahead of the probe. It exists so a
    caller can keep re-asserting an upstream condition (a manually-forced child alarm state, which
    real CloudWatch reverts on its own next evaluation cycle) for as long as this poll is waiting on
    a downstream effect of it.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        if before is not None:
            before()
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect", before=None
):
    """Poll for an async cross-service effect."""
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
        before=before,
    )


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
                Tags={"sim2real:managed": "true"},
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
        TreatMissingData="missing",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))


def _get_alarm_arn(ctx, name: str, composite: bool = False) -> str:
    cw = ctx.client("cloudwatch")
    # DescribeAlarms defaults AlarmTypes to ["MetricAlarm"] only -- composite alarms are
    # never returned unless AlarmTypes explicitly includes "CompositeAlarm".
    key = "CompositeAlarms" if composite else "MetricAlarms"
    alarm_types = ["CompositeAlarm"] if composite else ["MetricAlarm"]

    def _probe():
        resp = cw.describe_alarms(AlarmNames=[name], AlarmTypes=alarm_types)
        alarms = resp.get(key, [])
        return alarms[0]["AlarmArn"] if alarms else None

    return _poll_until(
        _probe,
        lambda r: r is not None,
        timeout_s=30.0,
        interval_s=2.0,
        description=f"alarm {name} visible via describe_alarms",
    )


def _wait_for_alarm_state(
    ctx, name: str, expected_state: str, composite: bool = False, timeout_s=60.0, interval_s=3.0,
    before=None,
) -> str:
    cw = ctx.client("cloudwatch")
    key = "CompositeAlarms" if composite else "MetricAlarms"
    alarm_types = ["CompositeAlarm"] if composite else ["MetricAlarm"]

    def _probe():
        alarms = cw.describe_alarms(AlarmNames=[name], AlarmTypes=alarm_types).get(key, [])
        return alarms[0]["StateValue"] if alarms else None

    return _poll_until(
        _probe,
        lambda s: s == expected_state,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"alarm {name} state == {expected_state}",
        before=before,
    )


def _wait_for_generic_marker(
    ctx, function_name: str, since_ms: int, contains: str, timeout_s=120.0, interval_s=5.0,
    before=None,
) -> list[str]:
    logs = ctx.client("logs")
    log_group = f"/aws/lambda/{function_name}"

    def _probe():
        try:
            resp = logs.filter_log_events(logGroupName=log_group, startTime=since_ms)
        except logs.exceptions.ResourceNotFoundException:
            return []
        return [ev["message"] for ev in resp.get("events", []) if "SIM2REAL_MARKER:" in ev["message"]]

    return _wait_for_effect(
        _probe,
        lambda r: any(contains in m for m in r),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"marker containing {contains!r} delivered to {function_name}",
        before=before,
    )


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
