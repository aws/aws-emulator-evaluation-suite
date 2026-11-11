"""deploy-ecs-capacity-provider-round-trip-then-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-ecs-capacity-provider-round-trip-then-delete"
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


# ---- Check-specific: the template, then run(). ----

def _template(cp_name: str, asg_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.61.0.0/16"}},
            "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.61.0.0/20", "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
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
                    "AutoScalingGroupArn": {"Ref": "Asg"},
                    "ManagedTerminationProtection": "DISABLED",
                },
                "Tags": [{"Key": "sim2real-cp", "Value": cp_name}],
            }},
        },
        "Outputs": {
            "CapacityProviderRef": {"Value": {"Ref": "CapacityProvider"}},
        },
    })


def _own_capacity_providers(ecs, prefix: str) -> list[str]:
    """Every capacity-provider name starting with ``prefix``, from an unfiltered, fully paged list.

    DescribeCapacityProviders has no botocore paginator and caps ``maxResults`` at 10, so the next
    token is followed by hand.
    """
    names: list[str] = []
    token = None
    while True:
        kw = {"maxResults": 10}
        if token:
            kw["nextToken"] = token
        resp = ecs.describe_capacity_providers(**kw)
        names.extend(p["name"] for p in resp["capacityProviders"])
        token = resp.get("nextToken")
        if not token:
            break
    return [n for n in names if n.startswith(prefix)]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ECS capacity provider on a zero-capacity Auto Scaling group reads back.

    Name, AutoScalingGroupArn, ManagedTerminationProtection and Tags match the template, and
    deleting the stack leaves it INACTIVE rather than unreadable.

    Reference: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/asg-capacity-providers.html
    """
    cfn = ctx.client("cloudformation")
    ecs = ctx.client("ecs")

    stack = ctx.unique_name("sim2real-cfncp-")
    cp_name = ctx.unique_name("sim2real-cfncp-cp-")
    asg_name = ctx.unique_name("sim2real-cfncp-asg-")

    stack_id = create_stack(ctx, cfn, stack, _template(cp_name, asg_name),
                             Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}, expected 'CREATE_COMPLETE'"
    )
    partition = stack_id.split(":")[1]

    out = stack_outputs(cfn, stack_id)
    ref = out["CapacityProviderRef"]
    assert ref == cp_name, f"Ref {ref!r} != the template's Name {cp_name!r}"

    # Ref against an independent read (an unfiltered, fully paged list), never a read keyed by Ref.
    listed = _own_capacity_providers(ecs, cp_name)
    assert listed == [cp_name], (
        f"an unfiltered, fully paged DescribeCapacityProviders lists {listed!r} starting with "
        f"{cp_name!r}, expected exactly [{cp_name!r}]"
    )

    described = ecs.describe_capacity_providers(
        capacityProviders=[cp_name], include=["TAGS"])["capacityProviders"]
    assert len(described) == 1, (
        f"DescribeCapacityProviders({cp_name!r}) returned {described!r}, expected 1 provider"
    )
    provider = described[0]
    assert provider["name"] == ref, f"provider name {provider['name']!r} != Ref {ref!r}"
    want_arn = f"arn:{partition}:ecs:{ctx.region}:{ctx.account}:capacity-provider/{cp_name}"
    assert provider["capacityProviderArn"] == want_arn, (
        f"capacityProviderArn {provider['capacityProviderArn']!r} != {want_arn!r}"
    )
    assert provider["status"] == "ACTIVE", (
        f"a freshly created capacity provider reports status {provider['status']!r}, expected "
        f"'ACTIVE'"
    )

    got_tags = {t["key"]: t["value"] for t in provider.get("tags", [])
                if not t["key"].startswith("aws:")}
    assert got_tags == {"sim2real": stack, "sim2real-cp": cp_name}, f"tags {got_tags!r}"

    # Every templated property of the AutoScalingGroupProvider.
    asg_provider = provider["autoScalingGroupProvider"]
    asg_tail = asg_provider["autoScalingGroupArn"].rsplit(":", 1)[-1]
    assert asg_tail == f"autoScalingGroupName/{asg_name}", (
        f"autoScalingGroupArn {asg_provider['autoScalingGroupArn']!r} does not name the ASG "
        f"{asg_name!r} the stack created"
    )
    assert asg_provider["managedTerminationProtection"] == "DISABLED", (
        f"managedTerminationProtection is {asg_provider['managedTerminationProtection']!r}, "
        f"expected 'DISABLED'"
    )

    delete_stack(cfn, stack_id)
    final = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"]
    assert len(final) == 1, (
        f"after the stack's delete, DescribeCapacityProviders({cp_name!r}) returned {final!r}; "
        f"a deleted capacity provider should still describe by name with a tombstone status"
    )
    assert final[0]["status"] == "INACTIVE", (
        f"after the stack's delete, capacity provider {cp_name!r} reports status "
        f"{final[0]['status']!r}, expected the documented tombstone 'INACTIVE'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
