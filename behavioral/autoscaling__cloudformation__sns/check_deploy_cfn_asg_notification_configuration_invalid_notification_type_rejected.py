"""deploy-cfn-asg-notification-configuration-invalid-notification-type-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-asg-notification-configuration-invalid-notification-type-rejected"
GROUP = "deploy"
SERVICES = ["autoscaling", "cloudformation", "sns"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})
_AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


def _wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by id every 2 s for a status in ``terminal``; return it."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def _delete_stack(cf, stack_id):
    """Delete by id and wait for a terminal delete status; raise unless it is DELETE_COMPLETE."""
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    cf.delete_stack(StackName=stack_id)
    status = _wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"})
    assert status == "DELETE_COMPLETE", f"stack {stack_id} delete ended {status!r}"


def _stack_events(cf, stack_id):
    """Every DescribeStackEvents row for the stack, oldest first."""
    rows = []
    kw = {"StackName": stack_id}
    while True:
        page = cf.describe_stack_events(**kw)
        rows.extend(page["StackEvents"])
        token = page.get("NextToken")
        if not token:
            break
        kw["NextToken"] = token
    return rows[::-1]


def _resource_failure_reason(events, logical_id, status):
    """The ``ResourceStatusReason`` of ``logical_id``'s most recent row in ``status``."""
    for e in events[::-1]:
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status:
            return e.get("ResourceStatusReason")
    raise AssertionError(f"no {status!r} event found for {logical_id!r} in {events!r}")


_HANDLER_WRAPPER_RE = re.compile(
    r'^Resource handler returned message: "(?P<msg>.*)" '
    r"\(RequestToken: [0-9a-f-]{36}, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$"
)
_SDK_WRAPPER_RE = re.compile(
    r"^(?P<text>.*) \(Service: AutoScaling, Status Code: 400, "
    r"Request ID: [0-9a-f-]{36}\) \(SDK Attempt Count: \d+\)$"
)


def _asg_handler_error(reason):
    """``(HandlerErrorCode, message)`` of a resource handler failure reason.

    Request ids and the SDK attempt count vary every call, so the wrapper regexes strip them
    by shape rather than pin their value.
    """
    outer = _HANDLER_WRAPPER_RE.match(reason or "")
    assert outer, f"resource status reason had an unexpected shape: {reason!r}"
    inner = _SDK_WRAPPER_RE.match(outer["msg"])
    assert inner, f"handler message had an unexpected shape: {outer['msg']!r}"
    return outer["code"], inner["text"]


def _template(subnet_id, asg_name, notification_types, topic_arn):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        # The public AMI parameter resolves inside CloudFormation, not through a check call.
        "Parameters": {"ImageId": {"Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                                   "Default": _AMI_PARAMETER}},
        "Resources": {
            "LaunchTemplate": {
                "Type": "AWS::EC2::LaunchTemplate",
                "Properties": {
                    "LaunchTemplateData": {
                        "ImageId": {"Ref": "ImageId"}, "InstanceType": "t3.micro"
                    },
                },
            },
            "ASG": {
                "Type": "AWS::AutoScaling::AutoScalingGroup",
                "Properties": {
                    "AutoScalingGroupName": asg_name,
                    "MinSize": "0",
                    "MaxSize": "0",
                    "DesiredCapacity": "0",
                    "VPCZoneIdentifier": [subnet_id],
                    "LaunchTemplate": {
                        "LaunchTemplateId": {"Ref": "LaunchTemplate"},
                        "Version": {"Fn::GetAtt": ["LaunchTemplate", "LatestVersionNumber"]},
                    },
                    "NotificationConfigurations": [
                        {"TopicARN": topic_arn, "NotificationTypes": notification_types}
                    ],
                },
            },
        },
    })


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation ASG naming a notification type outside the enum fails to create, and the
    identical template with a valid type deploys the group and its notification configuration.
    """
    cf = ctx.client("cloudformation")
    asgc = ctx.client("autoscaling")
    sns = ctx.client("sns")

    subnet_id = ctx.network().subnet_ids[0]
    topic_name = ctx.unique_name("sim2real-cfnasgnotifbad-topic-")
    topic_arn = sns.create_topic(Name=topic_name, Tags=[{"Key": "sim2real", "Value": topic_name}])[
        "TopicArn"
    ]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    bad_stack = ctx.unique_name("sim2real-cfnasgnotifbad-")
    bad_asg_name = ctx.unique_name("sim2real-cfnasgnotifbad-asg-")
    ctx.on_cleanup(lambda: _delete_stack(cf, bad_stack_id))
    bad_created = cf.create_stack(
        StackName=bad_stack,
        TemplateBody=_template(subnet_id, bad_asg_name, ["autoscaling:NOT_A_REAL_TYPE"], topic_arn),
        Tags=[{"Key": "sim2real", "Value": bad_stack}],
        DisableRollback=True,
    )
    bad_stack_id = bad_created["StackId"]

    status = _wait_stack(cf, bad_stack_id)
    assert status == "CREATE_FAILED", (
        f"stack {bad_stack_id} with an invalid notification type ended {status!r}"
    )
    reason = _resource_failure_reason(_stack_events(cf, bad_stack_id), "ASG", "CREATE_FAILED")
    code, message = _asg_handler_error(reason)
    assert (code, message) == (
        "InvalidRequest",
        '"autoscaling:NOT_A_REAL_TYPE" is not a valid Notification Type.',
    ), f"ASG CREATE_FAILED handler error was {(code, message)!r}"

    # CreateAutoScalingGroup takes no NotificationConfigurations: the group itself is created by
    # one call and PutNotificationConfiguration is a separate, later one, so the group exists
    # with no notification configuration once that later call is the one that failed.
    bad_group = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[bad_asg_name])[
        "AutoScalingGroups"
    ]
    assert len(bad_group) == 1, f"expected the group to exist despite CREATE_FAILED, got {bad_group!r}"
    bad_configs = asgc.describe_notification_configurations(AutoScalingGroupNames=[bad_asg_name])[
        "NotificationConfigurations"
    ]
    assert bad_configs == [], (
        f"group {bad_asg_name!r} should have no notification configuration after the rejected "
        f"type, got {bad_configs!r}"
    )

    # The identical template with a valid type deploys the group and its notification.
    good_stack = ctx.unique_name("sim2real-cfnasgnotifok-")
    good_asg_name = ctx.unique_name("sim2real-cfnasgnotifok-asg-")
    ctx.on_cleanup(lambda: _delete_stack(cf, good_stack_id))
    good_created = cf.create_stack(
        StackName=good_stack,
        TemplateBody=_template(
            subnet_id, good_asg_name, ["autoscaling:TEST_NOTIFICATION"], topic_arn
        ),
        Tags=[{"Key": "sim2real", "Value": good_stack}],
    )
    good_stack_id = good_created["StackId"]
    status = _wait_stack(cf, good_stack_id)
    assert status == "CREATE_COMPLETE", f"stack {good_stack_id} with a valid type ended {status!r}"
    configs = asgc.describe_notification_configurations(AutoScalingGroupNames=[good_asg_name])[
        "NotificationConfigurations"
    ]
    got = sorted((c["TopicARN"], c["NotificationType"]) for c in configs)
    assert got == [(topic_arn, "autoscaling:TEST_NOTIFICATION")], (
        f"control group {good_asg_name!r} notification configurations read {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
