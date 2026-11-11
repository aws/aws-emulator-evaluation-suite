"""deploy-cloudformation-schedule-invokes-target."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudformation-schedule-invokes-target"
GROUP = "deploy"
SERVICES = ["scheduler"]


# timing:real-time — schedule: 150 s
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A schedule deployed via CloudFormation (AWS::Scheduler::Schedule targeting an SQS queue,
    with its own execution role) actually fires and delivers a message to the queue after the
    stack reaches CREATE_COMPLETE -- not merely that the stack succeeded."""
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    schedule_name = ctx.unique_name("sim2real-behav-cfn-sched-")
    queue_name = ctx.unique_name("sim2real-behav-cfn-q-")
    payload = json.dumps({"hello": "from-cloudformation", "n": 42})

    # Give the stack ~2 minutes of buffer to reach CREATE_COMPLETE before the one-time
    # schedule is due to fire.
    fire_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=150)
    fire_at_str = fire_at.strftime("%Y-%m-%dT%H:%M:%S")

    template = _build_template()
    stack_name = _deploy_cfn(
        ctx,
        cfn,
        template,
        parameters={
            "ScheduleName": schedule_name,
            "QueueName": queue_name,
            "ScheduleExpression": f"at({fire_at_str})",
            "Payload": payload,
        },
    )

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    }
    queue_url = outputs["QueueUrl"]

    message = _poll_for_message(sqs, queue_url, timeout_s=300.0)
    assert message is not None, "CloudFormation-deployed schedule never delivered a message"
    assert message == payload, f"delivered body differs: wrote {payload!r}, got {message!r}"


def _build_template() -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "ScheduleName": {"Type": "String"},
            "QueueName": {"Type": "String"},
            "ScheduleExpression": {"Type": "String"},
            "Payload": {"Type": "String"},
        },
        "Resources": {
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
                                        "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "Schedule": {
                "Type": "AWS::Scheduler::Schedule",
                "Properties": {
                    "Name": {"Ref": "ScheduleName"},
                    "ScheduleExpression": {"Ref": "ScheduleExpression"},
                    "ScheduleExpressionTimezone": "UTC",
                    "FlexibleTimeWindow": {"Mode": "OFF"},
                    "Target": {
                        "Arn": {"Fn::GetAtt": ["Queue", "Arn"]},
                        "RoleArn": {"Fn::GetAtt": ["SchedulerRole", "Arn"]},
                        "Input": {"Ref": "Payload"},
                    },
                },
            },
        },
        "Outputs": {"QueueUrl": {"Value": {"Ref": "Queue"}}},
    }


def _deploy_cfn(ctx, cfn, template: dict, parameters: dict) -> str:
    stack_name = ctx.unique_name("sim2real-behav-cfn-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Capabilities=["CAPABILITY_IAM"],
        OnFailure="DELETE",
        Tags=[{"Key": "sim2real-check", "Value": "deploy-cloudformation-schedule-invokes-target"}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_confirm_gone(cfn, stack_name))

    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"unexpected stack status: {status}"
    return stack_name


def _delete_stack_and_confirm_gone(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    # Deleting the stack's SQS queue alone takes CloudFormation about a minute.
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    try:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if not (
            (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
        ):
            raise
        return
    assert status == "DELETE_COMPLETE", f"stack not torn down: {status}"


def _poll_for_message(sqs, queue_url: str, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return msg["Body"]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
