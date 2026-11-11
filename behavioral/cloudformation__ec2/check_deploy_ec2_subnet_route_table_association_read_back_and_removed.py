"""deploy-ec2-subnet-route-table-association-read-back-and-removed."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "deploy-ec2-subnet-route-table-association-read-back-and-removed"
GROUP = "deploy-cfn-resource-existence"
SERVICES = ["cloudformation", "ec2"]

VPC_BLOCK = "10.81.0.0/16"
SUBNET_BLOCK = "10.81.0.0/24"


def _template() -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Az": {"Type": "String"}},
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": VPC_BLOCK}},
            "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": SUBNET_BLOCK,
                "AvailabilityZone": {"Ref": "Az"}}},
            "RouteTable": {"Type": "AWS::EC2::RouteTable", "Properties": {"VpcId": {"Ref": "Vpc"}}},
            "Association": {"Type": "AWS::EC2::SubnetRouteTableAssociation", "Properties": {
                "SubnetId": {"Ref": "Subnet"}, "RouteTableId": {"Ref": "RouteTable"}}},
        },
        "Outputs": {"AssociationId": {"Value": {"Fn::GetAtt": ["Association", "Id"]}}},
    }


def _wait_create(cfn, stack_id: str, max_attempts: int = 150) -> dict[str, Any]:
    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": max_attempts})
    except WaiterError:
        pass
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _delete_stack_and_wait(cfn, stack_id: str, max_attempts: int = 150) -> None:
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
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert usable, "no available Availability Zone in this region"
    return usable[0]


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _settle_not_found(fn, want_code: str, deadline_s: float = 60.0, poll_s: float = 2.0) -> tuple[str, str]:
    """Poll until ``fn`` raises ``want_code`` (EC2 deletes are eventually consistent)."""
    deadline = time.monotonic() + deadline_s
    code = message = None
    while True:
        code, message = _error(fn)
        if code == want_code or time.monotonic() >= deadline:
            return code, message
        time.sleep(poll_s)


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN subnet/route-table association reads back through EC2's own Associations list with
    the template's SubnetId and RouteTableId. EC2 publishes no standalone Describe for the
    association itself, so its removal is provable only through the parent route table's NotFound.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    az = _usable_az(ec2)

    name = ctx.unique_name("sim2real-xsvc-rtbassoc-")
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
    assoc_id = outputs["AssociationId"]

    subnet_id = cfn.describe_stack_resource(
        StackName=stack_id, LogicalResourceId="Subnet")["StackResourceDetail"]["PhysicalResourceId"]
    rt_id = cfn.describe_stack_resource(
        StackName=stack_id, LogicalResourceId="RouteTable")["StackResourceDetail"]["PhysicalResourceId"]
    assoc_physical = cfn.describe_stack_resource(
        StackName=stack_id, LogicalResourceId="Association")["StackResourceDetail"]["PhysicalResourceId"]
    assert assoc_physical == assoc_id, (
        f"GetAtt Id {assoc_id!r} disagrees with the resource's own PhysicalResourceId "
        f"{assoc_physical!r}"
    )

    route_table = ec2.describe_route_tables(RouteTableIds=[rt_id])["RouteTables"][0]
    matches = [a for a in route_table["Associations"]
               if a.get("RouteTableAssociationId") == assoc_id]
    assert len(matches) == 1, (
        f"expected exactly one association {assoc_id!r} on route table {rt_id!r}, found "
        f"{route_table['Associations']!r}"
    )
    assoc = matches[0]
    assert assoc["SubnetId"] == subnet_id, (
        f"association's SubnetId is {assoc['SubnetId']!r}, expected the template's {subnet_id!r}"
    )
    assert assoc["RouteTableId"] == rt_id, (
        f"association's RouteTableId is {assoc['RouteTableId']!r}, expected the template's "
        f"{rt_id!r}"
    )

    network = _network_ids(cfn, stack_id)
    _delete_stack_and_wait(cfn, stack_id)
    code, message = _settle_not_found(
        lambda: ec2.describe_route_tables(RouteTableIds=[rt_id]), "InvalidRouteTableID.NotFound")
    assert code == "InvalidRouteTableID.NotFound", (
        f"expected InvalidRouteTableID.NotFound once the stack (and the association on it) is "
        f"deleted, got {code}: {message!r}"
    )
    assert message == f"The routeTable ID '{rt_id}' does not exist", f"unexpected message {message!r}"
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
