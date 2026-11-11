"""deploy-ec2-instance-read-back-and-removed."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "deploy-ec2-instance-read-back-and-removed"
GROUP = "deploy-cfn-resource-existence"
SERVICES = ["cloudformation", "ec2"]

INSTANCE_TYPE = "t3.micro"
AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
VPC_BLOCK = "10.82.0.0/16"
SUBNET_BLOCK = "10.82.0.0/24"

_GETATT_TO_FIELD = {
    "PrivateDnsName": "PrivateDnsName",
    "PrivateIp": "PrivateIpAddress",
    "VpcId": "VpcId",
}


def _template() -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "Az": {"Type": "String"},
            "Ami": {"Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                     "Default": AMI_PARAMETER},
        },
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": VPC_BLOCK}},
            "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": SUBNET_BLOCK,
                "AvailabilityZone": {"Ref": "Az"}}},
            "Instance": {"Type": "AWS::EC2::Instance", "Properties": {
                "ImageId": {"Ref": "Ami"}, "InstanceType": INSTANCE_TYPE,
                "SubnetId": {"Ref": "Subnet"},
            }},
        },
        "Outputs": {
            "InstanceId": {"Value": {"Fn::GetAtt": ["Instance", "InstanceId"]}},
            "PrivateDnsName": {"Value": {"Fn::GetAtt": ["Instance", "PrivateDnsName"]}},
            "PrivateIp": {"Value": {"Fn::GetAtt": ["Instance", "PrivateIp"]}},
            "VpcId": {"Value": {"Fn::GetAtt": ["Instance", "VpcId"]}},
        },
    }


def _wait_create(cfn, stack_id: str, max_attempts: int = 300) -> dict[str, Any]:
    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": max_attempts})
    except WaiterError:
        pass
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _delete_stack_and_wait(cfn, stack_id: str, max_attempts: int = 300) -> None:
    cfn.delete_stack(StackName=stack_id)
    try:
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": max_attempts})
    except WaiterError:
        pass
    final = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    if final["StackStatus"] != "DELETE_COMPLETE":
        raise RuntimeError(
            f"stack {stack_id} delete ended {final['StackStatus']!r}: "
            f"{final.get('StackStatusReason')!r}"
        )


def _usable_az(ec2) -> str:
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [INSTANCE_TYPE]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ offers {INSTANCE_TYPE!r}; offerings were {sorted(offered)!r}"
    return usable[0]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-launched EC2 instance reads back through DescribeInstances with every property and
    Fn::GetAtt value the template carries, and deleting the stack terminates it, which
    DescribeInstances reports as EC2's own terminal state for the id.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    az = _usable_az(ec2)

    name = ctx.unique_name("sim2real-xsvc-ec2inst-")
    stack_id = cfn.create_stack(
        StackName=name, TemplateBody=json.dumps(_template()),
        Parameters=[{"ParameterKey": "Az", "ParameterValue": az}],
        Tags=[{"Key": "sim2real", "Value": name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))

    stack = _wait_create(cfn, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), "
        f"expected 'CREATE_COMPLETE'"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    instance_id = outputs["InstanceId"]

    ec2.get_waiter("instance_running").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    inst = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    assert inst["InstanceType"] == INSTANCE_TYPE, (
        f"EC2 reports instance type {inst['InstanceType']!r}, expected {INSTANCE_TYPE!r}"
    )
    assert inst["SubnetId"] == cfn.describe_stack_resource(
        StackName=stack_id, LogicalResourceId="Subnet")["StackResourceDetail"]["PhysicalResourceId"], (
        f"EC2 reports the instance in subnet {inst['SubnetId']!r}, not the template's subnet"
    )
    for attr, field in _GETATT_TO_FIELD.items():
        want = outputs[attr]
        got = inst.get(field, "") or ""
        assert got == want, (
            f"EC2's {field} is {got!r}, but the stack's Fn::GetAtt Instance.{attr} is {want!r}"
        )

    network = _network_ids(cfn, stack_id)
    _delete_stack_and_wait(cfn, stack_id)
    # A terminated instance stays describable (EC2 does not purge it on delete), so its own
    # not-found signal is the terminal State.Name, not a NotFound error.
    ec2.get_waiter("instance_terminated").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    final = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    assert final["State"]["Name"] == "terminated", (
        f"expected the instance to be 'terminated' once the stack is deleted, EC2 reports "
        f"{final['State']['Name']!r}"
    )
    _assert_network_gone(ec2, network)


# What EC2 answers for each network resource the stack created, once the stack delete removed it.
_EC2_GONE = {
    "AWS::EC2::VPC": ("describe_vpcs", "VpcIds", "InvalidVpcID.NotFound", "The vpc ID '{}' does not exist"),
    "AWS::EC2::Subnet": (
        "describe_subnets", "SubnetIds", "InvalidSubnetID.NotFound", "The subnet ID '{}' does not exist"
    ),
    "AWS::EC2::SecurityGroup": (
        "describe_security_groups", "GroupIds", "InvalidGroup.NotFound", "The security group '{}' does not exist"
    ),
}


def _network_ids(cfn, stack: str) -> list[tuple[str, str]]:
    """``(resource type, physical id)`` of every VPC, subnet and security group in the stack."""
    return sorted(
        (r["ResourceType"], r["PhysicalResourceId"])
        for r in cfn.describe_stack_resources(StackName=stack)["StackResources"]
        if r["ResourceType"] in _EC2_GONE
    )


def _assert_network_gone(ec2, network: list[tuple[str, str]]) -> None:
    """Each network resource answers EC2's own not-found code and message."""
    for rtype, physical_id in network:
        op, param, code, message = _EC2_GONE[rtype]
        try:
            found = getattr(ec2, op)(**{param: [physical_id]})
        except ClientError as exc:
            got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        else:
            raise AssertionError(f"{rtype} {physical_id} still described after the stack delete: {found!r}")
        assert got == (code, message.format(physical_id)), (
            f"{rtype} {physical_id} after the stack delete: {got!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
