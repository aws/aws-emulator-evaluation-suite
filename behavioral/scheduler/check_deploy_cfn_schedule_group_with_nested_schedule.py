"""deploy-cfn-schedule-group-with-nested-schedule."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "deploy-cfn-schedule-group-with-nested-schedule"
GROUP = "deploy"
SERVICES = ["scheduler"]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN stack with a ScheduleGroup + nested Schedule is visible under that group."""
    cfn = ctx.client("cloudformation")
    scheduler = ctx.client("scheduler")

    stack_name = ctx.unique_name("sim2real-sched-cfn-grp-")
    group_name = ctx.unique_name("sim2real-sched-grp-")
    queue_name = ctx.unique_name("sim2real-sched-q-")
    role_name = ctx.unique_name("sim2real-sched-role-")
    schedule_name = ctx.unique_name("sim2real-sched-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "GroupName": {"Type": "String"},
            "ScheduleName": {"Type": "String"},
            "QueueName": {"Type": "String"},
            "RoleName": {"Type": "String"},
        },
        "Resources": {
            "MyGroup": {
                "Type": "AWS::Scheduler::ScheduleGroup",
                "Properties": {"Name": {"Ref": "GroupName"}},
            },
            "TargetQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": {"Ref": "QueueName"}},
            },
            "SchedulerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Ref": "RoleName"},
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "scheduler.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "AllowSendToQueue",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "sqs:SendMessage",
                                        "Resource": {"Fn::GetAtt": ["TargetQueue", "Arn"]},
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "MySchedule": {
                "Type": "AWS::Scheduler::Schedule",
                "Properties": {
                    "Name": {"Ref": "ScheduleName"},
                    "GroupName": {"Ref": "MyGroup"},
                    # Recurring, distant cadence -- this check asserts visibility under the
                    # group, not delivery, so it deliberately avoids ever firing.
                    "ScheduleExpression": "rate(1 day)",
                    "State": "DISABLED",
                    "FlexibleTimeWindow": {"Mode": "OFF"},
                    "Target": {
                        "Arn": {"Fn::GetAtt": ["TargetQueue", "Arn"]},
                        "RoleArn": {"Fn::GetAtt": ["SchedulerRole", "Arn"]},
                        "Input": "unused",
                    },
                },
            },
        },
    }

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[
            {"ParameterKey": "GroupName", "ParameterValue": group_name},
            {"ParameterKey": "ScheduleName", "ParameterValue": schedule_name},
            {"ParameterKey": "QueueName", "ParameterValue": queue_name},
            {"ParameterKey": "RoleName", "ParameterValue": role_name},
        ],
        Capabilities=["CAPABILITY_NAMED_IAM"],
        OnFailure="DELETE",
    )
    stack_deleted = [False]
    ctx.on_cleanup(lambda: None if stack_deleted[0] else _delete_stack(ctx, stack_name))

    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )

    pages = scheduler.get_paginator("list_schedule_groups").paginate(NamePrefix=group_name)
    groups = [g for page in pages for g in page["ScheduleGroups"]]
    assert any(g["Name"] == group_name and g["State"] == "ACTIVE" for g in groups), (
        f"schedule group {group_name} not visible via ListScheduleGroups"
    )

    schedules = scheduler.list_schedules(GroupName=group_name)["Schedules"]
    matching = [s for s in schedules if s["Name"] == schedule_name]
    assert len(matching) == 1, f"nested schedule {schedule_name} not visible under its group"
    assert matching[0]["GroupName"] == group_name, (
        f"expected GroupName {group_name!r}, got {matching[0]['GroupName']!r}"
    )

    # Tear down now (cleanup is made idempotent below) and prove CFN's delete actually
    # removed both the group and the schedule nested inside it, not merely the stack.
    _delete_stack(ctx, stack_name)
    stack_deleted[0] = True

    try:
        scheduler.get_schedule_group(Name=group_name)
        raise AssertionError(f"schedule group {group_name} still exists after stack deletion")
    except scheduler.exceptions.ResourceNotFoundException as exc:
        message = exc.response["Error"].get("Message")
        expected = f"Schedule group {group_name} does not exist."
        assert message == expected, f"expected {expected!r}, got {message!r}"

    try:
        scheduler.get_schedule(Name=schedule_name, GroupName=group_name)
        raise AssertionError(
            f"nested schedule {schedule_name} still exists after stack deletion"
        )
    except scheduler.exceptions.ResourceNotFoundException as exc:
        message = exc.response["Error"].get("Message")
        expected = f"Schedule group {group_name} does not exist."
        assert message == expected, f"expected {expected!r}, got {message!r}"


def _delete_stack(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
