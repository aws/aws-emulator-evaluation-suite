"""deploy-ec2-vpc-peering-connection-and-security-group-vpc-association-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-vpc-peering-connection-and-security-group-vpc-association-round-trip-and-delete"
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

_VPC1_CIDR = "10.92.0.0/16"
_VPC2_CIDR = "10.93.0.0/16"


def _template(tag_value: str) -> str:
    t = [{"Key": "sim2real-check", "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc1": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC1_CIDR, "Tags": t}},
            "Vpc2": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC2_CIDR, "Tags": t}},
            "Group": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {"GroupDescription": "sim2real peering/vpc-assoc group",
                                "VpcId": {"Ref": "Vpc1"}, "Tags": t},
            },
            "Peering": {
                "Type": "AWS::EC2::VPCPeeringConnection",
                "Properties": {"VpcId": {"Ref": "Vpc1"}, "PeerVpcId": {"Ref": "Vpc2"}, "Tags": t},
            },
            "GroupVpcAssociation": {
                "Type": "AWS::EC2::SecurityGroupVpcAssociation",
                "Properties": {"GroupId": {"Fn::GetAtt": ["Group", "GroupId"]},
                                "VpcId": {"Ref": "Vpc2"}},
            },
        },
        "Outputs": {
            "Vpc1Id": {"Value": {"Ref": "Vpc1"}},
            "Vpc2Id": {"Value": {"Ref": "Vpc2"}},
            "GroupId": {"Value": {"Fn::GetAtt": ["Group", "GroupId"]}},
            "PeeringId": {"Value": {"Ref": "Peering"}},
            "PeeringGetAttId": {"Value": {"Fn::GetAtt": ["Peering", "Id"]}},
            "AssociationVpcOwnerId": {
                "Value": {"Fn::GetAtt": ["GroupVpcAssociation", "VpcOwnerId"]},
            },
        },
    })


def _poll_vpc_association_state(ec2, group_id: str, vpc_id: str, want: str,
                                 deadline_s: float = 90.0) -> str:
    """Poll DescribeSecurityGroupVpcAssociations until the association reaches ``want``."""
    deadline = time.monotonic() + deadline_s
    state = None
    while True:
        rows = ec2.describe_security_group_vpc_associations(Filters=[
            {"Name": "group-id", "Values": [group_id]},
            {"Name": "vpc-id", "Values": [vpc_id]},
        ])["SecurityGroupVpcAssociations"]
        state = rows[0]["State"] if rows else "absent"
        if state == want or time.monotonic() >= deadline:
            return state
        time.sleep(2)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::EC2::VPCPeeringConnection auto-accepts between two VPCs in the same
    account, and an AWS::EC2::SecurityGroupVpcAssociation reaches 'associated' in EC2's own
    view; deleting the stack tombstones the peering at Status.Code 'deleted'.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpcpeeringconnection.html
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-ec2peer-")

    stack_id = create_stack(ctx, cfn, stack, _template(CHECK))

    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = stack_outputs(cfn, stack_id)
    vpc1_id, vpc2_id = outputs["Vpc1Id"], outputs["Vpc2Id"]
    group_id, peering_id = outputs["GroupId"], outputs["PeeringId"]

    peerings = ec2.describe_vpc_peering_connections(
        VpcPeeringConnectionIds=[peering_id])["VpcPeeringConnections"]
    assert peerings, f"DescribeVpcPeeringConnections({peering_id!r}) returned nothing"
    peering = peerings[0]
    got_ids = (peering_id, outputs["PeeringGetAttId"])
    assert got_ids == (peering["VpcPeeringConnectionId"],) * 2, (
        f"(Ref Peering, GetAtt Peering.Id) {got_ids!r}, EC2 reports "
        f"{peering['VpcPeeringConnectionId']!r}"
    )
    assert peering["RequesterVpcInfo"]["VpcId"] == vpc1_id, (
        f"expected RequesterVpcInfo.VpcId {vpc1_id!r}, EC2 reports "
        f"{peering['RequesterVpcInfo']['VpcId']!r}"
    )
    assert peering["AccepterVpcInfo"]["VpcId"] == vpc2_id, (
        f"expected AccepterVpcInfo.VpcId {vpc2_id!r}, EC2 reports "
        f"{peering['AccepterVpcInfo']['VpcId']!r}"
    )
    assert peering["Status"]["Code"] == "active", (
        f"expected a same-account peering to auto-accept to 'active', EC2 reports status "
        f"{peering['Status']!r}"
    )

    state = _poll_vpc_association_state(ec2, group_id, vpc2_id, "associated")
    assert state == "associated", (
        f"expected security group {group_id!r}'s association with VPC {vpc2_id!r} to settle at "
        f"'associated', last read was {state!r}"
    )
    rows = ec2.describe_security_group_vpc_associations(Filters=[
        {"Name": "group-id", "Values": [group_id]}, {"Name": "vpc-id", "Values": [vpc2_id]}])[
        "SecurityGroupVpcAssociations"]
    owners = [r.get("VpcOwnerId") for r in rows]
    assert owners == [outputs["AssociationVpcOwnerId"]], (
        f"GetAtt GroupVpcAssociation.VpcOwnerId {outputs['AssociationVpcOwnerId']!r}, EC2 "
        f"reports the association's VpcOwnerId {owners!r}"
    )

    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack), *stack_gone)

    rows = ec2.describe_security_group_vpc_associations(Filters=[
        {"Name": "group-id", "Values": [group_id]}, {"Name": "vpc-id", "Values": [vpc2_id]}])[
        "SecurityGroupVpcAssociations"]
    assert rows == [], (
        f"expected no security-group/VPC association left after the stack delete, got {rows!r}"
    )

    # A deleted peering connection is a documented tombstone, not a NotFound: it stays
    # describable with Status.Code "deleted".
    after_peerings = ec2.describe_vpc_peering_connections(
        VpcPeeringConnectionIds=[peering_id])["VpcPeeringConnections"]
    assert after_peerings, f"DescribeVpcPeeringConnections({peering_id!r}) returned nothing"
    after_status = after_peerings[0]["Status"]["Code"]
    assert after_status == "deleted", (
        f"expected the deleted peering's Status.Code to be 'deleted', EC2 reports "
        f"{after_status!r}"
    )

    security_groups_gone = (
        "InvalidGroup.NotFound",
        f"The security group '{group_id}' does not exist",
    )
    expect_error(lambda: ec2.describe_security_groups(GroupIds=[group_id]), *security_groups_gone)

    vpcs_gone = ("InvalidVpcID.NotFound", f"The vpc ID '{vpc1_id}' does not exist")
    expect_error(lambda: ec2.describe_vpcs(VpcIds=[vpc1_id]), *vpcs_gone)
    vpcs_gone = ("InvalidVpcID.NotFound", f"The vpc ID '{vpc2_id}' does not exist")
    expect_error(lambda: ec2.describe_vpcs(VpcIds=[vpc2_id]), *vpcs_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
