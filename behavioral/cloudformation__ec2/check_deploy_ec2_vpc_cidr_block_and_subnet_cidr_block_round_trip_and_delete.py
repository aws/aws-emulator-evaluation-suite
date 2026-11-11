"""deploy-ec2-vpc-cidr-block-and-subnet-cidr-block-round-trip-and-delete."""
from __future__ import annotations

import ipaddress
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-vpc-cidr-block-and-subnet-cidr-block-round-trip-and-delete"
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

_VPC_CIDR = "10.94.0.0/16"
_SUBNET_CIDR = "10.94.1.0/24"


def _template(tag_value: str, az: str) -> str:
    t = [{"Key": "sim2real-check", "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR, "Tags": t}},
            "Ipv6Block": {
                "Type": "AWS::EC2::VPCCidrBlock",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "AmazonProvidedIpv6CidrBlock": True},
            },
            "Subnet": {
                "Type": "AWS::EC2::Subnet",
                "DependsOn": "Ipv6Block",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR,
                                "AvailabilityZone": az, "Tags": t},
            },
            "SubnetIpv6Block": {
                "Type": "AWS::EC2::SubnetCidrBlock",
                "Properties": {
                    "SubnetId": {"Ref": "Subnet"},
                    "Ipv6CidrBlock": {
                        "Fn::Select": [0, {"Fn::Cidr": [
                            {"Fn::Select": [0, {"Fn::GetAtt": ["Vpc", "Ipv6CidrBlocks"]}]},
                            1, "64",
                        ]}]
                    },
                },
            },
        },
        "Outputs": {
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "SubnetId": {"Value": {"Ref": "Subnet"}},
            "VpcIpv6AssociationId": {"Value": {"Ref": "Ipv6Block"}},
            "SubnetIpv6AssociationId": {"Value": {"Ref": "SubnetIpv6Block"}},
            "VpcBlockGetAttId": {"Value": {"Fn::GetAtt": ["Ipv6Block", "Id"]}},
            "VpcBlockIpSource": {"Value": {"Fn::GetAtt": ["Ipv6Block", "IpSource"]}},
            "SubnetBlockGetAttId": {"Value": {"Fn::GetAtt": ["SubnetIpv6Block", "Id"]}},
            "SubnetBlockIpSource": {"Value": {"Fn::GetAtt": ["SubnetIpv6Block", "IpSource"]}},
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
    """A CloudFormation AWS::EC2::VPCCidrBlock adds an Amazon-provided IPv6 /56 that EC2's own
    DescribeVpcs reports under the Ref'd association id, and an AWS::EC2::SubnetCidrBlock slices
    a /64 of it onto the subnet; deleting the stack removes the subnet and the VPC.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpccidrblock.html
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-ec2cidr-")
    az = _usable_az(ec2)

    stack_id = create_stack(ctx, cfn, stack, _template(CHECK, az))

    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = stack_outputs(cfn, stack_id)
    vpc_id, subnet_id = outputs["VpcId"], outputs["SubnetId"]
    vpc_assoc_id, subnet_assoc_id = outputs["VpcIpv6AssociationId"], outputs["SubnetIpv6AssociationId"]

    vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    vpc_v6 = [b for b in vpc["Ipv6CidrBlockAssociationSet"]
              if b["AssociationId"] == vpc_assoc_id]
    assert len(vpc_v6) == 1, (
        f"expected exactly one IPv6 association {vpc_assoc_id!r} on VPC {vpc_id!r}, EC2 "
        f"reports {vpc['Ipv6CidrBlockAssociationSet']!r}"
    )
    assert vpc_v6[0]["Ipv6CidrBlockState"]["State"] == "associated", (
        f"expected the VPC's IPv6 association to be 'associated', EC2 reports "
        f"{vpc_v6[0]['Ipv6CidrBlockState']!r}"
    )
    got = (outputs["VpcBlockGetAttId"], outputs["VpcBlockIpSource"])
    want = (vpc_v6[0]["AssociationId"], vpc_v6[0].get("IpSource"))
    assert got == want, (
        f"VPCCidrBlock (GetAtt Id, GetAtt IpSource) {got!r}, EC2 reports {want!r}"
    )
    vpc_v6_cidr = vpc_v6[0]["Ipv6CidrBlock"]
    assert vpc_v6_cidr.endswith("/56"), (
        f"expected the VPC's Amazon-provided IPv6 CIDR to be a /56, EC2 reports {vpc_v6_cidr!r}"
    )

    subnet = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]
    subnet_v6 = [b for b in subnet["Ipv6CidrBlockAssociationSet"]
                 if b["AssociationId"] == subnet_assoc_id]
    assert len(subnet_v6) == 1, (
        f"expected exactly one IPv6 association {subnet_assoc_id!r} on subnet {subnet_id!r}, "
        f"EC2 reports {subnet['Ipv6CidrBlockAssociationSet']!r}"
    )
    assert subnet_v6[0]["Ipv6CidrBlockState"]["State"] == "associated", (
        f"expected the subnet's IPv6 association to be 'associated', EC2 reports "
        f"{subnet_v6[0]['Ipv6CidrBlockState']!r}"
    )
    got = (outputs["SubnetBlockGetAttId"], outputs["SubnetBlockIpSource"])
    want = (subnet_v6[0]["AssociationId"], subnet_v6[0].get("IpSource"))
    assert got == want, (
        f"SubnetCidrBlock (GetAtt Id, GetAtt IpSource) {got!r}, EC2 reports {want!r}"
    )
    subnet_v6_cidr = subnet_v6[0]["Ipv6CidrBlock"]
    assert subnet_v6_cidr.endswith("/64"), (
        f"expected the subnet's IPv6 CIDR to be a /64, EC2 reports {subnet_v6_cidr!r}"
    )
    vpc_v6_net = ipaddress.ip_network(vpc_v6_cidr, strict=False)
    subnet_v6_net = ipaddress.ip_network(subnet_v6_cidr, strict=False)
    assert subnet_v6_net.subnet_of(vpc_v6_net), (
        f"expected the subnet's IPv6 CIDR {subnet_v6_cidr!r} to be carved from the VPC's "
        f"{vpc_v6_cidr!r}"
    )

    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack), *stack_gone)

    subnets_gone = ("InvalidSubnetID.NotFound", f"The subnet ID '{subnet_id}' does not exist")
    expect_error(lambda: ec2.describe_subnets(SubnetIds=[subnet_id]), *subnets_gone)

    vpcs_gone = ("InvalidVpcID.NotFound", f"The vpc ID '{vpc_id}' does not exist")
    expect_error(lambda: ec2.describe_vpcs(VpcIds=[vpc_id]), *vpcs_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
