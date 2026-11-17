"""deploy-asg-lifecyclehook-notification-target-and-role-round-trip."""

from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-asg-lifecyclehook-notification-target-and-role-round-trip"
GROUP = "deploy"
SERVICES = ["autoscaling", "cloudformation", "iam", "sqs"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_FAILED",
        "UPDATE_ROLLBACK_FAILED",
        "IMPORT_COMPLETE",
        "IMPORT_ROLLBACK_COMPLETE",
        "IMPORT_ROLLBACK_FAILED",
    }
)
_DELETE_BUDGET_S = 600.0
_ASG_NOTIFICATION_POLICY = "policy/service-role/AutoScalingNotificationAccessRole"
_AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def handler_reason(reason):
    """``(masked message, HandlerErrorCode)`` of a resource-handler failure reason, masking only
    the per-call Request ID and SDK Attempt Count; compare the message with ==.
    """
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    message = re.sub(r"Request ID: [^,;)]+", "Request ID: <id>", m["message"])
    message = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", message)
    return message, m["code"]


def unable_to_publish(queue_arn, role_arn):
    """The LifecycleHook handler's exact refusal when ``role_arn`` cannot publish to the queue."""
    return (
        f"Unable to publish test message to notification target {queue_arn} using IAM role "
        f"{role_arn}. Please check your target and role configuration and try to put "
        f"lifecycle hook again. (Service: AutoScaling, Status Code: 400, Request ID: <id>) "
        f"(SDK Attempt Count: <n>)",
        "InvalidRequest",
    )


def wait_stack(ctx, cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"stack {stack_id}: the run budget ended first; not graded")
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(ctx, cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice."""
    deadline = time.monotonic() + _budget_s(ctx, _DELETE_BUDGET_S)
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in (
        "DELETE_IN_PROGRESS",
        "REVIEW_IN_PROGRESS",
    ):
        wait_stack(ctx, cf, stack_id, _TERMINAL, max(1.0, deadline - time.monotonic()))
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(
        ctx,
        cf,
        stack_id,
        {"DELETE_COMPLETE", "DELETE_FAILED"},
        max(1.0, deadline - time.monotonic()),
    )
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}")


def delete_stack_named(ctx, cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns."""
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                "ValidationError",
                f"Stack with id {name} does not exist",
            ):
                return
            raise
    delete_stack(ctx, cf, stack_id)


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, across all pages."""
    pages = cf.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    return [e for page in pages for e in page["StackEvents"]]


def hook_failure(cf, stack_id):
    """The masked reason on the stack's single LifecycleHook CREATE_FAILED row."""
    rows = [
        e.get("ResourceStatusReason")
        for e in stack_events(cf, stack_id)
        if e["LogicalResourceId"] == "LifecycleHook" and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(rows) == 1, f"expected exactly one LifecycleHook CREATE_FAILED row, got {rows!r}"
    return handler_reason(rows[0])


def create_hook_stack(ctx, cf, stack, template, queue_arn, role_arn, timeout_s=180.0):
    """CreateStack until CREATE_COMPLETE; return its StackId.

    PutLifecycleHook publishes the TEST_NOTIFICATION synchronously and fails while the role's
    just-attached policy is still propagating, so only that exact refusal re-creates the stack,
    within a bounded deadline; any other outcome raises.
    """
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    transient = unable_to_publish(queue_arn, role_arn)
    while True:
        created = {}
        ctx.on_cleanup(lambda c=created: delete_stack_named(ctx, cf, stack, c.get("StackId")))
        created["StackId"] = cf.create_stack(
            StackName=stack,
            TemplateBody=template,
            Tags=[{"Key": "sim2real", "Value": stack}],
        )["StackId"]
        stack_id = created["StackId"]
        status = wait_stack(ctx, cf, stack_id)
        if status == "CREATE_COMPLETE":
            return stack_id
        got = hook_failure(cf, stack_id)
        assert (status, got) == ("ROLLBACK_COMPLETE", transient), (
            f"stack {stack!r} ended {status!r} with {got!r}; only {transient!r} is retried"
        )
        delete_stack(ctx, cf, stack_id)
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"stack {stack!r}: the run budget ended first; not graded")
            raise AssertionError(f"stack {stack!r} still refused after {timeout_s:.0f}s: {got!r}")
        time.sleep(5)


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _template(subnet_id, asg_name, hook_name, role_arn, queue_arn):
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            # The public AMI parameter resolves inside CloudFormation, not through a check call.
            "Parameters": {
                "ImageId": {
                    "Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                    "Default": _AMI_PARAMETER,
                }
            },
            "Resources": {
                "LaunchTemplate": {
                    "Type": "AWS::EC2::LaunchTemplate",
                    "Properties": {
                        "LaunchTemplateData": {
                            "ImageId": {"Ref": "ImageId"},
                            "InstanceType": "t3.micro",
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
                    },
                },
                "LifecycleHook": {
                    "Type": "AWS::AutoScaling::LifecycleHook",
                    "Properties": {
                        "AutoScalingGroupName": {"Ref": "ASG"},
                        "LifecycleHookName": hook_name,
                        "LifecycleTransition": "autoscaling:EC2_INSTANCE_LAUNCHING",
                        "RoleARN": role_arn,
                        "NotificationTargetARN": queue_arn,
                        "HeartbeatTimeout": 60,
                        "DefaultResult": "ABANDON",
                    },
                },
            },
            "Outputs": {
                "AsgRef": {"Value": {"Ref": "ASG"}},
                "HookRef": {"Value": {"Ref": "LifecycleHook"}},
            },
        }
    )


def _create_sqs_queue(ctx):
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-q-")
    url = sqs.create_queue(QueueName=name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _create_asg_notification_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-asg-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "autoscaling.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = f"arn:{role_arn.split(':')[1]}:iam::aws:{_ASG_NOTIFICATION_POLICY}"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _poll_sqs_for_message(ctx, queue_url, predicate, timeout_s=90.0):
    sqs = ctx.client("sqs")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if isinstance(body, dict) and predicate(body):
                return body
    if _budget_spent(ctx):
        raise TimeoutError(f"{queue_url}: the run budget ended first; not graded")
    raise AssertionError(f"expected message not received on {queue_url} within {timeout_s}s")


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:deploy",
    "concern:representation",
    "concern:eventing",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation AWS::AutoScaling::LifecycleHook's NotificationTargetARN and RoleARN read
    back exactly through DescribeLifecycleHooks, and the queue receives a TEST_NOTIFICATION
    naming the group's ARN and account."""
    cf = ctx.client("cloudformation")
    asgc = ctx.client("autoscaling")

    queue_url, queue_arn = _create_sqs_queue(ctx)
    role_arn = _create_asg_notification_role(ctx)

    subnet_id = ctx.network().subnet_ids[0]
    stack = ctx.unique_name("sim2real-cfnhook-rt-")
    asg_name = ctx.unique_name("sim2real-cfnhook-rt-asg-")
    hook_name = ctx.unique_name("sim2real-cfnhook-rt-hook-")
    template = _template(subnet_id, asg_name, hook_name, role_arn, queue_arn)

    stack_id = create_hook_stack(ctx, cf, stack, template, queue_arn, role_arn)

    out = stack_outputs(cf, stack_id)
    assert (out["AsgRef"], out["HookRef"]) == (asg_name, hook_name), (
        f"Ref ASG / Ref LifecycleHook read {(out['AsgRef'], out['HookRef'])!r}, "
        f"expected {(asg_name, hook_name)!r}"
    )

    groups = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ]
    assert [g["AutoScalingGroupName"] for g in groups] == [asg_name], (
        f"DescribeAutoScalingGroups({asg_name!r}) returned {groups!r}"
    )
    group_arn = groups[0]["AutoScalingGroupARN"]

    hooks = asgc.describe_lifecycle_hooks(
        AutoScalingGroupName=asg_name, LifecycleHookNames=[hook_name]
    )["LifecycleHooks"]
    assert len(hooks) == 1, f"DescribeLifecycleHooks({hook_name!r}) returned {hooks!r}"
    hook = hooks[0]
    got = {"NotificationTargetARN": hook["NotificationTargetARN"], "RoleARN": hook["RoleARN"]}
    assert got == {"NotificationTargetARN": queue_arn, "RoleARN": role_arn}, (
        f"lifecycle hook {hook_name!r} reads {got!r}, expected the templated queue and role"
    )

    event = _poll_sqs_for_message(
        ctx,
        queue_url,
        lambda body: (
            body.get("AutoScalingGroupName") == asg_name
            and body.get("Event") == "autoscaling:TEST_NOTIFICATION"
        ),
    )
    got = (event.get("Service"), event.get("AutoScalingGroupARN"), event.get("AccountId"))
    want = ("AWS Auto Scaling", group_arn, ctx.account)
    assert got == want, (
        f"test notification (Service, AutoScalingGroupARN, AccountId) is {got!r}, expected {want!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
