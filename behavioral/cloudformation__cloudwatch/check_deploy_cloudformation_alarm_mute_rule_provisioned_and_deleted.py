"""deploy-cloudformation-alarm-mute-rule-provisioned-and-deleted."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudformation-alarm-mute-rule-provisioned-and-deleted"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudwatch"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_MUTE_RULE_GONE = ("ResourceNotFoundException", "")


@tags(
    "axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control",
)
def run(ctx) -> None:
    """A CFN-deployed AWS::CloudWatch::AlarmMuteRule really exists in CloudWatch with the
    template's schedule and mute target alarm, and stack deletion removes both.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_GetAlarmMuteRule.html
    """
    cf = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")

    stack_name = ctx.unique_name("sim2real-behav-mutestk-")
    alarm_name = ctx.unique_name("sim2real-behav-mutealarm-")
    mute_name = ctx.unique_name("sim2real-behav-muterule-")
    namespace = ctx.unique_name("Sim2RealBehavMute")

    template = {
        "Resources": {
            "TestAlarm": {
                "Type": "AWS::CloudWatch::Alarm",
                "Properties": {
                    "AlarmName": alarm_name,
                    "Namespace": namespace,
                    "MetricName": "ProbeMetric",
                    "Statistic": "Sum",
                    "Period": 60,
                    "EvaluationPeriods": 1,
                    "Threshold": 1,
                    "ComparisonOperator": "GreaterThanThreshold",
                },
            },
            "MuteRule": {
                "Type": "AWS::CloudWatch::AlarmMuteRule",
                "Properties": {
                    "Name": mute_name,
                    "Rule": {"Schedule": {"Expression": "cron(0 4 * * *)", "Duration": "PT1H"}},
                    "MuteTargets": {"AlarmNames": [{"Ref": "TestAlarm"}]},
                },
            },
        },
        "Outputs": {
            "MuteRef": {"Value": {"Ref": "MuteRule"}},
            "MuteArn": {"Value": {"Fn::GetAtt": ["MuteRule", "Arn"]}},
        },
    }

    stack_id = create_stack(ctx, cf, stack_name, json.dumps(template))
    status = wait_stack(cf, stack_id, timeout_s=240.0)
    assert status == "CREATE_COMPLETE", f"stack {stack_name!r} ended {status!r}, not CREATE_COMPLETE"

    outputs = stack_outputs(cf, stack_id)

    got = cw.get_alarm_mute_rule(AlarmMuteRuleName=mute_name)
    assert outputs["MuteRef"] == got["AlarmMuteRuleArn"], (
        f"Ref of the AlarmMuteRule should be its ARN {got['AlarmMuteRuleArn']!r}, "
        f"got {outputs['MuteRef']!r}"
    )
    assert outputs["MuteArn"] == got["AlarmMuteRuleArn"], (
        f"GetAtt Arn should equal {got['AlarmMuteRuleArn']!r}, got {outputs['MuteArn']!r}"
    )
    assert got["Rule"] == {"Schedule": {"Expression": "cron(0 4 * * *)", "Duration": "PT1H", "Timezone": "UTC"}}, (
        f"expected the template's schedule, got {got['Rule']!r}"
    )
    assert got["MuteTargets"] == {"AlarmNames": [alarm_name]}, (
        f"expected mute target {[alarm_name]!r}, got {got['MuteTargets']!r}"
    )
    assert got["Name"] == mute_name, f"expected mute rule name {mute_name!r}, got {got['Name']!r}"

    alarms = paginate(cw, "describe_alarms", "MetricAlarms", AlarmNames=[alarm_name],
                      AlarmTypes=["MetricAlarm"])
    assert len(alarms) == 1, f"expected the template's alarm {alarm_name!r}, got {len(alarms)} alarms"
    alarm = alarms[0]
    got_alarm = (
        alarm["Namespace"], alarm["MetricName"], alarm["Statistic"], alarm["Period"],
        alarm["EvaluationPeriods"], alarm["Threshold"], alarm["ComparisonOperator"],
    )
    want_alarm = (namespace, "ProbeMetric", "Sum", 60, 1, 1.0, "GreaterThanThreshold")
    assert got_alarm == want_alarm, f"expected the template's alarm {want_alarm!r}, got {got_alarm!r}"

    delete_stack(cf, stack_id)
    expect_error(lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=mute_name), *_MUTE_RULE_GONE)

    left = paginate(cw, "describe_alarms", "MetricAlarms", AlarmNames=[alarm_name],
                    AlarmTypes=["MetricAlarm"])
    assert left == [], f"alarm {alarm_name!r} still present after stack deletion ({len(left)} found)"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
