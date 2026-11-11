"""deploy-ecs-capacity-provider-with-nonexistent-asg-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-ecs-capacity-provider-with-nonexistent-asg-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecs"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


# ---- Check-specific: the template, then run(). ----

def _template(cp_name: str, asg_name: str, autoscaling_group_arn) -> str:
    resources = {
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.62.0.0/16"}},
        "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.62.0.0/20", "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
        }},
        "InstanceRole": {"Type": "AWS::IAM::Role", "Properties": {
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow",
                               "Principal": {"Service": "ec2.amazonaws.com"},
                               "Action": "sts:AssumeRole"}],
            },
            "ManagedPolicyArns": [{"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/"
                                              "service-role/AmazonEC2ContainerServiceforEC2Role"}],
        }},
        "InstanceProfile": {"Type": "AWS::IAM::InstanceProfile", "Properties": {
            "Roles": [{"Ref": "InstanceRole"}],
        }},
        "LaunchTemplate": {"Type": "AWS::EC2::LaunchTemplate", "Properties": {
            "LaunchTemplateData": {
                "ImageId": (
                    "{{resolve:ssm:/aws/service/ecs/optimized-ami/amazon-linux-2/"
                    "recommended/image_id}}"
                ),
                "InstanceType": "t3.micro",
                "IamInstanceProfile": {"Arn": {"Fn::GetAtt": ["InstanceProfile", "Arn"]}},
            },
        }},
        "Asg": {"Type": "AWS::AutoScaling::AutoScalingGroup", "Properties": {
            "AutoScalingGroupName": asg_name,
            "LaunchTemplate": {
                "LaunchTemplateId": {"Ref": "LaunchTemplate"},
                "Version": {"Fn::GetAtt": ["LaunchTemplate", "LatestVersionNumber"]},
            },
            "MinSize": "0", "MaxSize": "1", "DesiredCapacity": "0",
            "VPCZoneIdentifier": [{"Ref": "Subnet"}],
        }},
        "CapacityProvider": {"Type": "AWS::ECS::CapacityProvider", "Properties": {
            "Name": cp_name,
            "AutoScalingGroupProvider": {
                "AutoScalingGroupArn": autoscaling_group_arn,
                "ManagedTerminationProtection": "DISABLED",
            },
        }},
    }
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": {"CapacityProviderRef": {"Value": {"Ref": "CapacityProvider"}}},
    })


def _own_capacity_providers(ecs, name: str) -> list[dict]:
    """Every capacity provider named ``name``, from an unfiltered, fully paged list.

    DescribeCapacityProviders has no botocore paginator, so the next token is followed by hand.
    """
    found, token = [], None
    while True:
        kw = {"maxResults": 10, **({"nextToken": token} if token else {})}
        resp = ecs.describe_capacity_providers(**kw)
        found.extend(p for p in resp["capacityProviders"] if p["name"] == name)
        token = resp.get("nextToken")
        if not token:
            return found


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ECS capacity provider naming a nonexistent Auto Scaling group is refused.

    ECS's error rolls the stack back with no provider, while the same template naming the stack's
    own Auto Scaling group creates one.
    """
    cfn = ctx.client("cloudformation")
    ecs = ctx.client("ecs")
    good_cp = ctx.unique_name("sim2real-cfncp-vc-cp-")
    good_asg = ctx.unique_name("sim2real-cfncp-vc-asg-")
    bad_cp = ctx.unique_name("sim2real-cfncp-bad-cp-")
    bad_asg = ctx.unique_name("sim2real-cfncp-bad-asg-")
    missing_asg = ctx.unique_name("sim2real-cfncp-missing-asg-")

    # Positive control: the same template, AutoScalingGroupArn naming the stack's own group.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfncp-vc-stk-"),
                           _template(good_cp, good_asg, {"Ref": "Asg"}),
                           Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, good_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    control = [(p["status"], p["autoScalingGroupProvider"]["autoScalingGroupArn"].rsplit(":", 1)[1],
                p["autoScalingGroupProvider"]["managedTerminationProtection"])
               for p in _own_capacity_providers(ecs, good_cp)]
    assert control == [("ACTIVE", f"autoScalingGroupName/{good_asg}", "DISABLED")], (
        f"control capacity provider reads {control!r}"
    )

    # The one bad property: AutoScalingGroupArn names a group that does not exist.
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfncp-bad-stk-"),
                          _template(bad_cp, bad_asg, missing_asg),
                          Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, bad_id, timeout_s=600.0)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    reason = failed_reason(stack_events(cfn, bad_id), "CapacityProvider")
    got = handler_reason(reason, ctx.account, missing_asg)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through ECS, by the provider's declared name, BEFORE this check deletes.
    left = _own_capacity_providers(ecs, bad_cp)
    assert left == [], f"the rolled-back capacity provider is listed: {left!r}"


_REJECTED = (
    "Invalid request provided: CreateCapacityProvider error: The specified Auto Scaling group "
    "does not exist. Specify a valid Auto Scaling group and try again. (Service: Ecs, Status "
    "Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
