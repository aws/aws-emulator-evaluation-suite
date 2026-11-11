"""deploy-cloudformation-schedule-group-membership-behaves."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "deploy-cloudformation-schedule-group-membership-behaves"
GROUP = "deploy"
SERVICES = ["scheduler"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed AWS::Scheduler::ScheduleGroup with a nested Schedule resource shows the
    group as ACTIVE and the schedule as ENABLED and listed under that group via ListSchedules
    after the stack reaches CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    scheduler = ctx.client("scheduler")

    group_name = ctx.unique_name("sim2real-behav-cfn-group-")
    schedule_name = ctx.unique_name("sim2real-behav-cfn-gsched-")
    queue_name = ctx.unique_name("sim2real-behav-cfn-gq-")

    template = _build_template()
    stack_name = _deploy_cfn(
        ctx,
        cfn,
        scheduler,
        template,
        parameters={
            "GroupName": group_name,
            "ScheduleName": schedule_name,
            "QueueName": queue_name,
        },
        group_name=group_name,
    )
    del stack_name  # cleanup already registered inside _deploy_cfn

    group = scheduler.get_schedule_group(Name=group_name)
    assert group["State"] == "ACTIVE", f"expected group State ACTIVE, got {group['State']!r}"

    listing = scheduler.list_schedules(GroupName=group_name)
    matches = [s for s in listing["Schedules"] if s["Name"] == schedule_name]
    assert len(matches) == 1, (
        f"expected exactly one schedule named {schedule_name!r} under group {group_name!r}, "
        f"found {[s['Name'] for s in listing['Schedules']]}"
    )
    assert matches[0]["GroupName"] == group_name
    assert matches[0]["State"] == "ENABLED", f"expected schedule State ENABLED, got {matches[0]['State']!r}"


def _build_template() -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "GroupName": {"Type": "String"},
            "ScheduleName": {"Type": "String"},
            "QueueName": {"Type": "String"},
        },
        "Resources": {
            "ScheduleGroup": {
                "Type": "AWS::Scheduler::ScheduleGroup",
                "Properties": {"Name": {"Ref": "GroupName"}},
            },
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": {"Ref": "QueueName"}},
            },
            "SchedulerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "scheduler.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    }
                },
            },
            "Schedule": {
                "Type": "AWS::Scheduler::Schedule",
                "Properties": {
                    "Name": {"Ref": "ScheduleName"},
                    "GroupName": {"Ref": "ScheduleGroup"},
                    "ScheduleExpression": "rate(1 day)",
                    "FlexibleTimeWindow": {"Mode": "OFF"},
                    "State": "ENABLED",
                    "Target": {
                        "Arn": {"Fn::GetAtt": ["Queue", "Arn"]},
                        "RoleArn": {"Fn::GetAtt": ["SchedulerRole", "Arn"]},
                    },
                },
            },
        },
    }


def _deploy_cfn(ctx, cfn, scheduler, template: dict, parameters: dict, group_name: str) -> str:
    stack_name = ctx.unique_name("sim2real-behav-cfn-gstack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Capabilities=["CAPABILITY_IAM"],
        OnFailure="DELETE",
    )
    ctx.on_cleanup(lambda: _teardown_stack(cfn, scheduler, stack_name, group_name))

    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"unexpected stack status: {status}"
    return stack_name


def _teardown_stack(cfn, scheduler, stack_name: str, group_name: str) -> None:
    """Delete the stack, wait for it to actually finish, and prove the CFN-managed
    ScheduleGroup is gone via an independent scheduler read (not a CFN status word)."""
    cfn.delete_stack(StackName=stack_name)
    # Deleting the stack's SQS queue alone takes CloudFormation about a minute.
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    try:
        scheduler.get_schedule_group(Name=group_name)
        raise AssertionError(f"schedule group {group_name!r} still visible after stack delete")
    except scheduler.exceptions.ResourceNotFoundException as exc:
        message = exc.response["Error"].get("Message")
        expected = f"Schedule group {group_name} does not exist."
        assert message == expected, f"expected {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
