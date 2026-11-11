"""cloudwatch-alarm-state-change-eventbridge-invokes-lambda-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "cloudwatch-alarm-state-change-eventbridge-invokes-lambda-positive"
GROUP = "event-propagation"
SERVICES = ["cloudwatch", "lambda", "logs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudWatch metric alarm transitioning to ALARM state is delivered, via EventBridge's
    built-in 'CloudWatch Alarm State Change' event and a rule wired with put_targets, to invoke
    a Lambda function; the invocation payload contains the alarm's name and new state."""
    role_arn = _create_lambda_role(ctx)
    function_name = _create_marker_function(ctx, role_arn, _LAMBDA_CODE_GENERIC)
    function_arn = ctx.client("lambda").get_function(FunctionName=function_name)["Configuration"]["FunctionArn"]

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
    rule_arn = events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED")["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    events.tag_resource(ResourceARN=rule_arn, Tags=[{"Key": "sim2real", "Value": CHECK}])

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
    cw = ctx.client("cloudwatch")
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="sim2real behavioral check")
    _wait_for_alarm_state(ctx, alarm_name, "ALARM")

    markers = _wait_for_generic_marker(ctx, function_name, since_ms, alarm_name, timeout_s=120)
    assert any(alarm_name in m and '"value": "ALARM"' in m for m in markers), (
        f"expected alarm {alarm_name!r} in ALARM state in {markers!r}"
    )


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
        TreatMissingData="missing",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))


def _get_alarm_arn(ctx, name: str, composite: bool = False) -> str:
    cw = ctx.client("cloudwatch")
    key = "CompositeAlarms" if composite else "MetricAlarms"
    resp = cw.describe_alarms(AlarmNames=[name])
    return resp[key][0]["AlarmArn"]


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
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
