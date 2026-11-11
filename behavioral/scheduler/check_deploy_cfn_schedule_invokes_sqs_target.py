"""deploy-cfn-schedule-invokes-sqs-target."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "deploy-cfn-schedule-invokes-sqs-target"
GROUP = "deploy"
SERVICES = ["scheduler"]


# timing:real-time — schedule: 240 s
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A schedule deployed via CloudFormation actually fires and delivers to its SQS target."""
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    scheduler = ctx.client("scheduler")

    stack_name = ctx.unique_name("sim2real-sched-cfn-")
    queue_name = ctx.unique_name("sim2real-sched-q-")
    role_name = ctx.unique_name("sim2real-sched-role-")
    schedule_name = ctx.unique_name("sim2real-sched-")
    message_body = f"payload-{ctx.unique_name('marker-')}"

    # Give CFN a generous lead time to create the queue/role/schedule before the
    # one-time "at()" expression's fire time arrives.
    fire_dt = datetime.now(timezone.utc) + timedelta(minutes=4)
    fire_time = fire_dt.strftime("%Y-%m-%dT%H:%M:%S")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "ScheduleName": {"Type": "String"},
            "QueueName": {"Type": "String"},
            "RoleName": {"Type": "String"},
            "FireTime": {"Type": "String"},
            "MessageBody": {"Type": "String"},
        },
        "Resources": {
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
                    "ScheduleExpression": {"Fn::Sub": "at(${FireTime})"},
                    "FlexibleTimeWindow": {"Mode": "OFF"},
                    "Target": {
                        "Arn": {"Fn::GetAtt": ["TargetQueue", "Arn"]},
                        "RoleArn": {"Fn::GetAtt": ["SchedulerRole", "Arn"]},
                        "Input": {"Ref": "MessageBody"},
                    },
                },
            },
        },
    }

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[
            {"ParameterKey": "ScheduleName", "ParameterValue": schedule_name},
            {"ParameterKey": "QueueName", "ParameterValue": queue_name},
            {"ParameterKey": "RoleName", "ParameterValue": role_name},
            {"ParameterKey": "FireTime", "ParameterValue": fire_time},
            {"ParameterKey": "MessageBody", "ParameterValue": message_body},
        ],
        Capabilities=["CAPABILITY_NAMED_IAM"],
        OnFailure="DELETE",
    )
    stack_deleted = False

    def _cleanup_stack():
        if not stack_deleted:
            _delete_stack(ctx, stack_name)

    ctx.on_cleanup(_cleanup_stack)

    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )

    schedule = scheduler.get_schedule(Name=schedule_name)
    assert schedule["State"] == "ENABLED", f"expected ENABLED, got {schedule['State']!r}"
    assert schedule["Arn"].endswith(f"schedule/default/{schedule_name}"), (
        f"expected arn ending schedule/default/{schedule_name}, got {schedule['Arn']!r}"
    )

    queue_url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
    deadline = fire_dt + timedelta(minutes=3)
    message = _poll_for_message(sqs, queue_url, deadline)
    assert message is not None, "CFN-deployed schedule never delivered to its SQS target"
    assert message["Body"] == message_body, (
        f"expected body {message_body!r}, got {message['Body']!r}"
    )

    _delete_stack(ctx, stack_name)
    stack_deleted = True

    try:
        scheduler.get_schedule(Name=schedule_name)
        raise AssertionError("schedule still exists after its CFN stack was deleted")
    except scheduler.exceptions.ResourceNotFoundException as exc:
        got = exc.response["Error"].get("Message")
        expected = f"Schedule {schedule_name} does not exist."
        assert got == expected, f"expected {expected!r}, got {got!r}"

    try:
        sqs.get_queue_url(QueueName=queue_name)
        raise AssertionError("queue still exists after its CFN stack was deleted")
    except sqs.exceptions.QueueDoesNotExist as exc:
        got = exc.response["Error"].get("Message")
        expected = "The specified queue does not exist."
        assert got == expected, f"expected {expected!r}, got {got!r}"


def _poll_for_message(sqs, queue_url, deadline):
    while datetime.now(timezone.utc) < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=10)
        messages = resp.get("Messages", [])
        if messages:
            return messages[0]
    return None


def _delete_stack(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
