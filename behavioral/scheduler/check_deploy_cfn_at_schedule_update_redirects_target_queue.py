"""deploy-cfn-at-schedule-update-redirects-target-queue."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-at-schedule-update-redirects-target-queue"
GROUP = "deploy"
SERVICES = ["scheduler"]

#: Seconds from now to the first at() fire: the stack create (two queues, a role, the schedule)
#: completes well inside it.
_CREATE_LEAD_S = 120
#: Seconds from now to the second at() fire: the stack update (the schedule alone) completes well
#: inside it.
_UPDATE_LEAD_S = 90


# timing:real-time — schedule: 120 s
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Updating a CFN stack's one-time schedule Target redirects its next invocation to the new
    queue; the old queue receives nothing further.

    Reference: https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
    """
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    stack_name = ctx.unique_name("sim2real-sched-cfn-upd-")
    queue_a_name = ctx.unique_name("sim2real-sched-qa-")
    queue_b_name = ctx.unique_name("sim2real-sched-qb-")
    role_name = ctx.unique_name("sim2real-sched-role-")
    schedule_name = ctx.unique_name("sim2real-sched-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "ScheduleName": {"Type": "String"},
            "QueueAName": {"Type": "String"},
            "QueueBName": {"Type": "String"},
            "RoleName": {"Type": "String"},
            "FireTime": {"Type": "String"},
            "MessageBody": {"Type": "String"},
            "UseQueueB": {"Type": "String", "AllowedValues": ["true", "false"], "Default": "false"},
        },
        "Conditions": {"IsQueueB": {"Fn::Equals": [{"Ref": "UseQueueB"}, "true"]}},
        "Resources": {
            "QueueA": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": {"Ref": "QueueAName"}}},
            "QueueB": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": {"Ref": "QueueBName"}}},
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
                            "PolicyName": "AllowSendToQueues",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "sqs:SendMessage",
                                        "Resource": [
                                            {"Fn::GetAtt": ["QueueA", "Arn"]},
                                            {"Fn::GetAtt": ["QueueB", "Arn"]},
                                        ],
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
                        "Arn": {
                            "Fn::If": [
                                "IsQueueB",
                                {"Fn::GetAtt": ["QueueB", "Arn"]},
                                {"Fn::GetAtt": ["QueueA", "Arn"]},
                            ]
                        },
                        "RoleArn": {"Fn::GetAtt": ["SchedulerRole", "Arn"]},
                        "Input": {"Ref": "MessageBody"},
                    },
                },
            },
        },
    }

    # The first fire leaves room for the stack create; the second for the stack update.
    fire1 = datetime.now(timezone.utc) + timedelta(seconds=_CREATE_LEAD_S)
    params = [
        {"ParameterKey": "ScheduleName", "ParameterValue": schedule_name},
        {"ParameterKey": "QueueAName", "ParameterValue": queue_a_name},
        {"ParameterKey": "QueueBName", "ParameterValue": queue_b_name},
        {"ParameterKey": "RoleName", "ParameterValue": role_name},
        {"ParameterKey": "FireTime", "ParameterValue": fire1.strftime("%Y-%m-%dT%H:%M:%S")},
        {"ParameterKey": "MessageBody", "ParameterValue": "deploy-update-target-a"},
        {"ParameterKey": "UseQueueB", "ParameterValue": "false"},
    ]

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=params,
        Capabilities=["CAPABILITY_NAMED_IAM"],
        OnFailure="DELETE",
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )

    queue_a_url = sqs.get_queue_url(QueueName=queue_a_name)["QueueUrl"]
    queue_b_url = sqs.get_queue_url(QueueName=queue_b_name)["QueueUrl"]

    first = _poll_for_message(ctx, sqs, queue_a_url, fire1 + timedelta(minutes=3))
    assert first is not None, "initial deploy never delivered to queue A"
    assert first["Body"] == "deploy-update-target-a", f"expected deploy-update-target-a, got {first['Body']!r}"
    sqs.delete_message(QueueUrl=queue_a_url, ReceiptHandle=first["ReceiptHandle"])

    fire2 = datetime.now(timezone.utc) + timedelta(seconds=_UPDATE_LEAD_S)
    updated_params = [
        {"ParameterKey": "ScheduleName", "ParameterValue": schedule_name},
        {"ParameterKey": "QueueAName", "ParameterValue": queue_a_name},
        {"ParameterKey": "QueueBName", "ParameterValue": queue_b_name},
        {"ParameterKey": "RoleName", "ParameterValue": role_name},
        {"ParameterKey": "FireTime", "ParameterValue": fire2.strftime("%Y-%m-%dT%H:%M:%S")},
        {"ParameterKey": "MessageBody", "ParameterValue": "deploy-update-target-b"},
        {"ParameterKey": "UseQueueB", "ParameterValue": "true"},
    ]
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=updated_params,
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    cfn.get_waiter("stack_update_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )

    second = _poll_for_message(ctx, sqs, queue_b_url, fire2 + timedelta(minutes=3))
    assert second is not None, "post-update schedule never delivered to queue B"
    assert second["Body"] == "deploy-update-target-b", f"expected deploy-update-target-b, got {second['Body']!r}"

    # Queue A must not receive anything further: the updated Target points at B now.
    stray = _poll_for_message(ctx, sqs, queue_a_url, datetime.now(timezone.utc) + timedelta(seconds=10))
    assert stray is None, "old target queue A received a message after the target was updated"


def _poll_for_message(ctx, sqs, queue_url, deadline):
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, datetime.now(timezone.utc) + timedelta(seconds=max(1.0, left - 30.0)))
    while datetime.now(timezone.utc) < deadline:
        remaining = max(1, int((deadline - datetime.now(timezone.utc)).total_seconds()))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=min(10, remaining)
        )
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
    try:
        cfn.describe_stacks(StackName=stack_name)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code != "ValidationError":
            raise AssertionError(f"expected ValidationError for a torn-down stack, got {code}") from exc
        message = exc.response["Error"].get("Message")
        expected = f"Stack with id {stack_name} does not exist"
        assert message == expected, f"expected {expected!r}, got {message!r}"
    else:
        raise AssertionError(f"stack {stack_name} still describable by name after teardown")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
