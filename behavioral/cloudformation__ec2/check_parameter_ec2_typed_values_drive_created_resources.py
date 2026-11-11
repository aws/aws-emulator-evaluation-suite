"""parameter-ec2-typed-values-drive-created-resources."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-ec2-typed-values-drive-created-resources"
GROUP = "stack_parameters"
SERVICES = ["cloudformation", "ec2"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_DEADLINE_S = 240.0
_PORT = 8443

_TEMPLATE = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {
        "VpcId": {"Type": "AWS::EC2::VPC::Id"},
        "PeerGroup": {"Type": "AWS::EC2::SecurityGroup::Id"},
        "Subnets": {"Type": "List<AWS::EC2::Subnet::Id>"},
    },
    "Resources": {
        "AppGroup": {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {
                "GroupDescription": "sim2real typed parameter",
                "VpcId": {"Ref": "VpcId"},
                "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
            },
        },
        "FromPeer": {
            "Type": "AWS::EC2::SecurityGroupIngress",
            "Properties": {
                "GroupId": {"Fn::GetAtt": ["AppGroup", "GroupId"]},
                "IpProtocol": "tcp", "FromPort": _PORT, "ToPort": _PORT,
                "SourceSecurityGroupId": {"Ref": "PeerGroup"},
            },
        },
    },
    "Outputs": {
        "AppGroup": {"Value": {"Fn::GetAtt": ["AppGroup", "GroupId"]}},
        "Second": {"Value": {"Fn::Select": [1, {"Ref": "Subnets"}]}},
        "Joined": {"Value": {"Fn::Join": ["|", {"Ref": "Subnets"}]}},
    },
})


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises, except the named not-found codes."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _settle(cf, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves *_IN_PROGRESS; return the stack."""
    deadline = time.monotonic() + _DEADLINE_S
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"{stack_id} still {stack['StackStatus']!r} after {_DEADLINE_S}s")
        time.sleep(3.0)


def _delete_stack(cf, stack_id: str) -> None:
    """DeleteStack, then poll by StackId to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cf.delete_stack(StackName=stack_id)
    # The first read after DeleteStack may still show the prior status, so only the two terminal
    # delete states end the poll.
    deadline = time.monotonic() + _DEADLINE_S
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if stack["StackStatus"] == "DELETE_COMPLETE":
            return
        if stack["StackStatus"] == "DELETE_FAILED" or time.monotonic() > deadline:
            raise AssertionError(
                f"stack {stack_id} ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
            )
        time.sleep(3.0)


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EC2-typed parameters feed real resources: the stack's security group lands in the VPC passed as
    AWS::EC2::VPC::Id with ingress from the group passed in, and a subnet list indexes in order;
    DeleteStack then removes that group, which DescribeSecurityGroups reports as InvalidGroup.NotFound.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cloudformation-supplied-parameter-types.html
    """
    cf = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")

    tag = [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-ec2typed-")}, *_TAGS]
    vpc = ec2.create_vpc(CidrBlock="10.72.0.0/16", TagSpecifications=[
        {"ResourceType": "vpc", "Tags": tag}])["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=vpc), "InvalidVpcID.NotFound"))
    zone = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])[0]
    subnets = []
    for cidr in ("10.72.1.0/24", "10.72.2.0/24"):
        sid = ec2.create_subnet(VpcId=vpc, CidrBlock=cidr, AvailabilityZone=zone, TagSpecifications=[
            {"ResourceType": "subnet", "Tags": tag}])["Subnet"]["SubnetId"]
        ctx.on_cleanup(_teardown(lambda s=sid: ec2.delete_subnet(SubnetId=s), "InvalidSubnetID.NotFound"))
        subnets.append(sid)
    peer = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-ec2typed-peer-"), Description="sim2real", VpcId=vpc,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}])["GroupId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_security_group(GroupId=peer), "InvalidGroup.NotFound"))

    summary = cf.get_template_summary(TemplateBody=_TEMPLATE)
    types = {p["ParameterKey"]: p["ParameterType"] for p in summary["Parameters"]}
    assert types == {"VpcId": "AWS::EC2::VPC::Id", "PeerGroup": "AWS::EC2::SecurityGroup::Id",
                     "Subnets": "List<AWS::EC2::Subnet::Id>"}, f"GetTemplateSummary ParameterType: {types!r}"

    stack_id = cf.create_stack(
        StackName=ctx.unique_name("sim2real-behav-ec2typed-"), TemplateBody=_TEMPLATE, Tags=_TAGS,
        Parameters=[
            {"ParameterKey": "VpcId", "ParameterValue": vpc},
            {"ParameterKey": "PeerGroup", "ParameterValue": peer},
            {"ParameterKey": "Subnets", "ParameterValue": ",".join(subnets)},
        ],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    stack = _settle(cf, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"got {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack["Outputs"]}
    app = cf.describe_stack_resource(
        StackName=stack_id, LogicalResourceId="AppGroup")["StackResourceDetail"]["PhysicalResourceId"]
    assert outputs == {"AppGroup": app, "Second": subnets[1], "Joined": "|".join(subnets)}, f"outputs: {outputs!r}"

    group = ec2.describe_security_groups(GroupIds=[app])["SecurityGroups"][0]
    assert group["VpcId"] == vpc, f"the stack's group must be in the VPC parameter {vpc}; got {group['VpcId']!r}"
    rules = [
        (p["IpProtocol"], p["FromPort"], p["ToPort"], sorted(g["GroupId"] for g in p["UserIdGroupPairs"]))
        for p in group["IpPermissions"]
    ]
    assert rules == [("tcp", _PORT, _PORT, [peer])], f"ingress on the stack's group: {rules!r}"

    _delete_stack(cf, stack_id)
    try:
        ec2.describe_security_groups(GroupIds=[app])
    except ClientError as exc:
        code, message = exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    else:
        raise AssertionError(f"the stack's group {app} survived DeleteStack")
    assert code == "InvalidGroup.NotFound", f"after DeleteStack the stack's group gave code {code!r}"
    assert message == f"The security group '{app}' does not exist", (
        f"after DeleteStack the stack's group gave message {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
