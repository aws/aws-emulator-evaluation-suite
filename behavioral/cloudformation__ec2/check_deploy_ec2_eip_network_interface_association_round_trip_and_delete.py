"""deploy-ec2-eip-network-interface-association-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-eip-network-interface-association-round-trip-and-delete"
GROUP = "deploy-ec2-resource-sweep"
SERVICES = ["cloudformation", "ec2"]

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


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_VPC_CIDR = "10.91.0.0/16"
_SUBNET_CIDR = "10.91.1.0/24"
_ENI_DESC = "sim2real network interface for an EIP association"


def _template(tag_value: str, az: str) -> str:
    t = [{"Key": "sim2real-check", "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR, "Tags": t}},
            "Subnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR,
                                "AvailabilityZone": az, "Tags": t},
            },
            "Igw": {"Type": "AWS::EC2::InternetGateway", "Properties": {"Tags": t}},
            "Attachment": {
                "Type": "AWS::EC2::VPCGatewayAttachment",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "InternetGatewayId": {"Ref": "Igw"}},
            },
            "Eni": {
                "Type": "AWS::EC2::NetworkInterface",
                "Properties": {"SubnetId": {"Ref": "Subnet"}, "Description": _ENI_DESC, "Tags": t},
            },
            "Eip": {
                "Type": "AWS::EC2::EIP",
                "DependsOn": "Attachment",
                "Properties": {"Domain": "vpc", "Tags": t},
            },
            "Association": {
                "Type": "AWS::EC2::EIPAssociation",
                "Properties": {
                    "AllocationId": {"Fn::GetAtt": ["Eip", "AllocationId"]},
                    "NetworkInterfaceId": {"Ref": "Eni"},
                },
            },
        },
        "Outputs": {
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "SubnetId": {"Value": {"Ref": "Subnet"}},
            "EniId": {"Value": {"Ref": "Eni"}},
            "EipAllocationId": {"Value": {"Fn::GetAtt": ["Eip", "AllocationId"]}},
            "EipPublicIp": {"Value": {"Ref": "Eip"}},
            "AssociationId": {"Value": {"Ref": "Association"}},
        },
    })


def _usable_az(ec2) -> str:
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert usable, "no available Availability Zone in this region"
    return usable[0]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::EC2::EIP, ::NetworkInterface and ::EIPAssociation produce a VPC
    address bound to the declared ENI in EC2's own DescribeAddresses view; deleting the stack
    releases the address and removes the interface, each answering its own NotFound code.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-eip.html
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-ec2eipeni-")
    az = _usable_az(ec2)

    stack_id = create_stack(ctx, cfn, stack, _template(CHECK, az))

    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = stack_outputs(cfn, stack_id)
    vpc_id, subnet_id, eni_id = outputs["VpcId"], outputs["SubnetId"], outputs["EniId"]
    alloc_id, public_ip = outputs["EipAllocationId"], outputs["EipPublicIp"]
    association_id = outputs["AssociationId"]

    eni_before = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])["NetworkInterfaces"]
    assert eni_before, f"DescribeNetworkInterfaces({eni_id!r}) returned no interfaces"
    assert eni_before[0]["NetworkInterfaceId"] == eni_id, (
        f"expected the ENI's id to be the Ref value {eni_id!r}, EC2 reports "
        f"{eni_before[0]['NetworkInterfaceId']!r}"
    )
    assert eni_before[0]["SubnetId"] == subnet_id, (
        f"expected the ENI's SubnetId to be {subnet_id!r}, EC2 reports "
        f"{eni_before[0]['SubnetId']!r}"
    )
    assert eni_before[0]["Description"] == _ENI_DESC, (
        f"expected the ENI's Description to be {_ENI_DESC!r}, EC2 reports "
        f"{eni_before[0]['Description']!r}"
    )

    addrs = ec2.describe_addresses(AllocationIds=[alloc_id])["Addresses"]
    assert addrs, f"DescribeAddresses({alloc_id!r}) returned no addresses"
    addr = addrs[0]
    assert addr["AllocationId"] == alloc_id, (
        f"expected the address's AllocationId to be the GetAtt value {alloc_id!r}, EC2 reports "
        f"{addr['AllocationId']!r}"
    )
    assert addr["Domain"] == "vpc", f"expected Domain 'vpc', EC2 reports {addr['Domain']!r}"
    assert addr["PublicIp"] == public_ip, (
        f"expected the address's PublicIp to be the Ref value {public_ip!r}, EC2 reports "
        f"{addr['PublicIp']!r}"
    )
    assert addr["NetworkInterfaceId"] == eni_id, (
        f"expected the address to be associated to ENI {eni_id!r}, EC2 reports "
        f"{addr.get('NetworkInterfaceId')!r}"
    )
    assert addr.get("AssociationId") == association_id, (
        f"expected the address's AssociationId to be the EIPAssociation Ref {association_id!r}, "
        f"EC2 reports {addr.get('AssociationId')!r}"
    )

    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack), *stack_gone)

    addresses_gone = (
        "InvalidAllocationID.NotFound",
        f"The allocation ID '{alloc_id}' does not exist",
    )
    expect_error(lambda: ec2.describe_addresses(AllocationIds=[alloc_id]), *addresses_gone)

    network_interfaces_gone = (
        "InvalidNetworkInterfaceID.NotFound",
        f"The networkInterface ID '{eni_id}' does not exist",
    )
    expect_error(
        lambda: ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id]),
        *network_interfaces_gone,
    )

    subnets_gone = ("InvalidSubnetID.NotFound", f"The subnet ID '{subnet_id}' does not exist")
    expect_error(lambda: ec2.describe_subnets(SubnetIds=[subnet_id]), *subnets_gone)

    vpcs_gone = ("InvalidVpcID.NotFound", f"The vpc ID '{vpc_id}' does not exist")
    expect_error(lambda: ec2.describe_vpcs(VpcIds=[vpc_id]), *vpcs_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
