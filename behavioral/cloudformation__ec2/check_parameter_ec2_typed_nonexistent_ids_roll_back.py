"""parameter-ec2-typed-nonexistent-ids-roll-back."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-ec2-typed-nonexistent-ids-roll-back"
GROUP = "stack_parameters"
SERVICES = ["cloudformation", "ec2"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_DEADLINE_S = 240.0

_TEMPLATE = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {
        "VpcId": {"Type": "AWS::EC2::VPC::Id"},
        "GroupId": {"Type": "AWS::EC2::SecurityGroup::Id"},
        "Subnets": {"Type": "List<AWS::EC2::Subnet::Id>"},
    },
    "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    "Outputs": {
        "Vpc": {"Value": {"Ref": "VpcId"}},
        "Group": {"Value": {"Ref": "GroupId"}},
        "Subnets": {"Value": {"Fn::Join": [",", {"Ref": "Subnets"}]}},
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


def _network(ctx, ec2):
    """A VPC with one subnet and one security group, each deleted in teardown."""
    tag = [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-ec2param-")}, *_TAGS]
    vpc = ec2.create_vpc(CidrBlock="10.71.0.0/16", TagSpecifications=[
        {"ResourceType": "vpc", "Tags": tag}])["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=vpc), "InvalidVpcID.NotFound"))
    zone = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])[0]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.71.1.0/24", AvailabilityZone=zone, TagSpecifications=[
        {"ResourceType": "subnet", "Tags": tag}])["Subnet"]["SubnetId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_subnet(SubnetId=subnet), "InvalidSubnetID.NotFound"))
    group = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-ec2param-sg-"), Description="sim2real", VpcId=vpc,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}])["GroupId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_security_group(GroupId=group), "InvalidGroup.NotFound"))
    return vpc, subnet, group


def _params(vpc: str, group: str, subnets: str) -> list:
    return [
        {"ParameterKey": "VpcId", "ParameterValue": vpc},
        {"ParameterKey": "GroupId", "ParameterValue": group},
        {"ParameterKey": "Subnets", "ParameterValue": subnets},
    ]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """An AWS::EC2::* typed parameter naming an id that does not exist is accepted by CreateStack, then
    rolled back (ROLLBACK_COMPLETE) with a stack event naming the value and the parameter, and the
    stack's one resource never created; the ids the check made deploy.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cloudformation-supplied-parameter-types.html
    """
    cf = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    vpc, subnet, group = _network(ctx, ec2)

    good = cf.create_stack(StackName=ctx.unique_name("sim2real-behav-ec2param-ok-"), TemplateBody=_TEMPLATE,
                           Parameters=_params(vpc, group, subnet), Tags=_TAGS)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, good))
    stack = _settle(cf, good)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"real ids must deploy; got {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack["Outputs"]}
    assert outputs == {"Vpc": vpc, "Group": group, "Subnets": subnet}, f"outputs: {outputs!r}"

    suffix = uuid.uuid4().hex[:17]
    missing_vpc, missing_group, missing_subnet = f"vpc-{suffix}", f"sg-{suffix}", f"subnet-{suffix}"
    cases = (
        ("VpcId", _params(missing_vpc, group, subnet), missing_vpc),
        ("GroupId", _params(vpc, missing_group, subnet), missing_group),
        ("Subnets", _params(vpc, group, f"{subnet},{missing_subnet}"), missing_subnet),
    )
    for key, params, value in cases:
        name = ctx.unique_name("sim2real-behav-ec2param-bad-")
        stack_id = cf.create_stack(StackName=name, TemplateBody=_TEMPLATE, Parameters=params, Tags=_TAGS)["StackId"]
        ctx.on_cleanup(lambda s=stack_id: _delete_stack(cf, s))
        final = _settle(cf, stack_id)
        assert final["StackStatus"] == "ROLLBACK_COMPLETE", (
            f"a nonexistent {key} must roll the stack back; got {final['StackStatus']!r}: "
            f"{final.get('StackStatusReason')!r}"
        )
        rollback_reasons = [
            e["ResourceStatusReason"]
            for e in cf.describe_stack_events(StackName=stack_id)["StackEvents"]
            if e["LogicalResourceId"] == name and e["ResourceStatus"] == "ROLLBACK_IN_PROGRESS"
        ]
        expected_reason = (
            f"Parameter validation failed: parameter value {value} for parameter name {key} does not exist. "
            "Rollback requested by user."
        )
        assert rollback_reasons == [expected_reason], f"nonexistent {key}: rollback reasons {rollback_reasons!r}"
        try:
            cf.describe_stack_resource(StackName=name, LogicalResourceId="Handle")
        except ClientError as exc:
            handle_err = (exc.response["Error"]["Code"], exc.response["Error"]["Message"])
        else:
            raise AssertionError(f"the Handle resource must never be created for a refused {key}")
        assert handle_err == ("ValidationError", f"Resource Handle does not exist for stack {name}"), (
            f"nonexistent {key}: describing the never-created Handle said {handle_err!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
