"""deploy-cloudwatch-log-alarm-threshold-update-in-place-then-rename-replaces."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cloudwatch-log-alarm-threshold-update-in-place-then-rename-replaces"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudwatch"]

_TERMINAL_STACK_STATUSES = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})

_QUERY = "fields @timestamp | stats count(*) as lineCount"
_AGGREGATION = "count(*)"
_SCHEDULE = "rate(5 minutes)"


def _poll_stack_status(cf, stack_id: str, *, budget_s: float = 300.0) -> str:
    """Poll DescribeStacks for ``stack_id`` until its status is terminal; return that status."""
    deadline = time.monotonic() + budget_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL_STACK_STATUSES:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {budget_s:.0f}s")
        time.sleep(3)


def _destroy_stack(cf, stack_id: str, *, budget_s: float = 300.0) -> None:
    """Delete ``stack_id`` and wait for DELETE_COMPLETE; raise naming the cause otherwise."""
    current = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if current == "DELETE_COMPLETE":
        return
    cf.delete_stack(StackName=stack_id)
    status = _poll_stack_status(cf, stack_id, budget_s=budget_s)
    assert status == "DELETE_COMPLETE", f"stack {stack_id} delete ended {status!r}"


def _template(alarm_name: str, log_group_name: str, threshold: float) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "logs.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    return json.dumps({
        "Resources": {
            "LogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {"LogGroupName": log_group_name},
            },
            "QueryRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": trust,
                    "Policies": [{
                        "PolicyName": "query",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {"Effect": "Allow", "Action": "logs:StartQuery",
                                 "Resource": {"Fn::GetAtt": ["LogGroup", "Arn"]}},
                                {"Effect": "Allow", "Action": ["logs:GetQueryResults", "logs:StopQuery"],
                                 "Resource": "*"},
                            ],
                        },
                    }],
                },
            },
            "Alarm": {
                "Type": "AWS::CloudWatch::LogAlarm",
                "Properties": {
                    "AlarmName": alarm_name,
                    "ComparisonOperator": "GreaterThanOrEqualToThreshold",
                    "Threshold": threshold,
                    "QueryResultsToEvaluate": 1,
                    "QueryResultsToAlarm": 1,
                    "ScheduledQueryConfiguration": {
                        "QueryString": _QUERY,
                        "AggregationExpression": _AGGREGATION,
                        "ScheduledQueryRoleARN": {"Fn::GetAtt": ["QueryRole", "Arn"]},
                        "ScheduleConfiguration": {
                            "ScheduleExpression": _SCHEDULE,
                            "StartTimeOffset": 300,
                        },
                        "LogGroupIdentifiers": [{"Ref": "LogGroup"}],
                    },
                },
            },
        },
        "Outputs": {"AlarmRef": {"Value": {"Ref": "Alarm"}}},
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed log alarm's Threshold updates in place without replacing the alarm, and
    renaming it (its one createOnly property) replaces it with a resource carrying the latest
    threshold; stack deletion removes the replacement.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudwatch-logalarm.html
    """
    cf = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")

    stack_name = ctx.unique_name("sim2real-behav-cwlathrstk-")
    log_group_name = ctx.unique_name("sim2real-behav-cwlathrlg-")
    alarm_name_1 = ctx.unique_name("sim2real-behav-cwlathralm1-")
    alarm_name_2 = ctx.unique_name("sim2real-behav-cwlathralm2-")

    stack_id = cf.create_stack(
        StackName=stack_name, TemplateBody=_template(alarm_name_1, log_group_name, 5.0),
        Capabilities=["CAPABILITY_IAM"], Tags=[{"Key": "sim2real", "Value": stack_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _destroy_stack(cf, stack_id))

    status = _poll_stack_status(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack_name!r} ended {status!r}, not CREATE_COMPLETE"

    alarms = cw.describe_alarms(AlarmNames=[alarm_name_1], AlarmTypes=["LogAlarm"])["LogAlarms"]
    assert len(alarms) == 1, f"expected exactly one log alarm named {alarm_name_1!r}, got {alarms!r}"
    arn_before_update = alarms[0]["AlarmArn"]
    assert alarms[0]["Threshold"] == 5.0, f"expected Threshold 5.0, got {alarms[0]['Threshold']!r}"

    # ---- Update in place: Threshold changes; the alarm's ARN does not. ----
    cf.update_stack(
        StackName=stack_id, TemplateBody=_template(alarm_name_1, log_group_name, 10.0),
        Capabilities=["CAPABILITY_IAM"],
    )
    status = _poll_stack_status(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"threshold update ended {status!r}, not UPDATE_COMPLETE"

    alarms = cw.describe_alarms(AlarmNames=[alarm_name_1], AlarmTypes=["LogAlarm"])["LogAlarms"]
    assert len(alarms) == 1, f"expected the same log alarm {alarm_name_1!r} to survive, got {alarms!r}"
    assert alarms[0]["Threshold"] == 10.0, f"expected the updated Threshold 10.0, got {alarms[0]['Threshold']!r}"
    assert alarms[0]["AlarmArn"] == arn_before_update, (
        f"an in-place update should keep the same ARN {arn_before_update!r}, got {alarms[0]['AlarmArn']!r}"
    )

    # ---- Renaming the alarm (its createOnly property) replaces it. ----
    cf.update_stack(
        StackName=stack_id, TemplateBody=_template(alarm_name_2, log_group_name, 10.0),
        Capabilities=["CAPABILITY_IAM"],
    )
    status = _poll_stack_status(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"rename update ended {status!r}, not UPDATE_COMPLETE"

    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack["Outputs"]}
    assert outputs["AlarmRef"] == alarm_name_2, (
        f"Ref after the rename should be the new name {alarm_name_2!r}, got {outputs['AlarmRef']!r}"
    )

    remaining = cw.describe_alarms(
        AlarmNames=[alarm_name_1, alarm_name_2], AlarmTypes=["LogAlarm"]
    )["LogAlarms"]
    remaining_names = {a["AlarmName"] for a in remaining}
    assert remaining_names == {alarm_name_2}, (
        f"expected only the replacement {alarm_name_2!r} to remain, got {sorted(remaining_names)!r}"
    )
    replacement = remaining[0]
    assert replacement["Threshold"] == 10.0, (
        f"the replacement should carry the latest Threshold 10.0, got {replacement['Threshold']!r}"
    )
    assert replacement["AlarmArn"] != arn_before_update, (
        f"a replaced resource should mint a new ARN, still got {arn_before_update!r}"
    )

    _destroy_stack(cf, stack_id)
    after_delete = cw.describe_alarms(
        AlarmNames=[alarm_name_1, alarm_name_2], AlarmTypes=["LogAlarm"]
    )["LogAlarms"]
    assert after_delete == [], (
        f"expected no log alarm named {alarm_name_1!r} or {alarm_name_2!r} after stack deletion, "
        f"got {after_delete!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
