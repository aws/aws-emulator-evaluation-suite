"""deploy-directconnect-gateway-association-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-directconnect-gateway-association-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "directconnect", "ec2"]

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

_VPC_CIDR = "10.202.0.0/16"


def _template(dgw_name: str) -> str:
    """A VPC with an attached VPN gateway and a Direct Connect gateway associated with it."""
    t = [{"Key": "sim2real-check", "Value": dgw_name}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR, "Tags": t}},
            "Vgw": {"Type": "AWS::EC2::VPNGateway", "Properties": {"Type": "ipsec.1", "Tags": t}},
            "Attach": {
                "Type": "AWS::EC2::VPCGatewayAttachment",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "VpnGatewayId": {"Ref": "Vgw"}},
            },
            "Dgw": {
                "Type": "AWS::DirectConnect::DirectConnectGateway",
                "Properties": {"DirectConnectGatewayName": dgw_name, "Tags": t},
            },
            "Assoc": {
                "Type": "AWS::DirectConnect::DirectConnectGatewayAssociation",
                "DependsOn": "Attach",
                "Properties": {
                    "DirectConnectGatewayId": {"Fn::GetAtt": ["Dgw", "DirectConnectGatewayId"]},
                    "AssociatedGatewayId": {"Ref": "Vgw"},
                },
            },
        },
        "Outputs": {
            "DgwArn": {"Value": {"Ref": "Dgw"}},
            "DgwId": {"Value": {"Fn::GetAtt": ["Dgw", "DirectConnectGatewayId"]}},
            "VgwId": {"Value": {"Ref": "Vgw"}},
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "AssocId": {"Value": {"Ref": "Assoc"}},
        },
    })


def _gateway_state(dc, dgw_id: str) -> str:
    gateways = dc.describe_direct_connect_gateways(directConnectGatewayId=dgw_id)[
        "directConnectGateways"]
    assert len(gateways) == 1, f"expected one gateway record for {dgw_id!r}, got {len(gateways)}"
    return gateways[0]["directConnectGatewayState"]


def _poll_state(poll, want, *, deadline_s: float = 180.0, poll_s: float = 2.0):
    """Poll ``poll()`` until it returns ``want`` or the deadline passes; return the last value."""
    deadline = time.monotonic() + deadline_s
    while True:
        state = poll()
        if state == want or time.monotonic() >= deadline:
            return state
        time.sleep(poll_s)


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::DirectConnect::DirectConnectGatewayAssociation of a Direct Connect
    gateway with the stack's VPN gateway reads back as associated with the VPC's CIDR, and
    deleting the stack removes the association, both gateways and the VPC.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-directconnect-directconnectgatewayassociation.html
    """
    dc = ctx.client("directconnect")
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-assocrt-")
    dgw_name = ctx.unique_name("sim2real-dgw-")

    stack_id = create_stack(ctx, cfn, stack, _template(dgw_name))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"
    )

    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    dgw_id, vgw_id, vpc_id, assoc_id = (
        outputs["DgwId"], outputs["VgwId"], outputs["VpcId"], outputs["AssocId"]
    )
    # GetAtt id and Ref against an independent read: the gateways listed by the declared name.
    listed = [g["directConnectGatewayId"]
              for g in paginate(dc, "describe_direct_connect_gateways", "directConnectGateways")
              if g["directConnectGatewayName"] == dgw_name]
    assert listed == [dgw_id], f"the gateways named {dgw_name!r} are {listed!r}, GetAtt {dgw_id!r}"
    want_dgw_arn = f"arn:{partition}:directconnect::{ctx.account}:dx-gateway/{dgw_id}"
    assert outputs["DgwArn"] == want_dgw_arn, (
        f"expected Ref Dgw {want_dgw_arn!r}, got {outputs['DgwArn']!r}"
    )
    gateways = dc.describe_direct_connect_gateways(directConnectGatewayId=dgw_id)[
        "directConnectGateways"]
    assert [(g["directConnectGatewayName"], g["directConnectGatewayState"]) for g in gateways] == [
        (dgw_name, "available")
    ], f"expected one available gateway named {dgw_name!r}, Direct Connect reports {gateways!r}"

    # The template tag on each tagged resource, exactly; the stack's own sim2real tag is not
    # asserted here.
    want_tags = {"sim2real-check": dgw_name}
    gw_tags = [{t["key"]: t.get("value") for t in r["tags"]}
               for r in dc.describe_tags(resourceArns=[want_dgw_arn])["resourceTags"]
               if r["resourceArn"] == want_dgw_arn]
    got = [{k: v for k, v in t.items() if k != "sim2real" and not k.startswith("aws:")}
           for t in gw_tags]
    assert got == [want_tags], f"the gateway's tags are {gw_tags!r}"
    vgws = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"]
    vpcs = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]
    for label, found in (("VPN gateway", vgws), ("VPC", vpcs)):
        got = [{t["Key"]: t["Value"] for t in r.get("Tags", [])
                if t["Key"] != "sim2real" and not t["Key"].startswith("aws:")} for r in found]
        assert got == [want_tags], f"the {label}'s tags are {found!r}"
    got_vgw = [(v["Type"], [(a["VpcId"], a["State"]) for a in v["VpcAttachments"]]) for v in vgws]
    assert got_vgw == [("ipsec.1", [(vpc_id, "attached")])], (
        f"expected the ipsec.1 VPN gateway attached to {vpc_id!r}, EC2 reports {vgws!r}"
    )
    assert [v["CidrBlock"] for v in vpcs] == [_VPC_CIDR], (
        f"expected the VPC's CidrBlock {_VPC_CIDR!r}, EC2 reports {vpcs!r}"
    )

    assocs = dc.describe_direct_connect_gateway_associations(
        directConnectGatewayId=dgw_id, associatedGatewayId=vgw_id
    )["directConnectGatewayAssociations"]
    assert len(assocs) == 1, (
        f"expected exactly one association between {dgw_id!r} and {vgw_id!r}, got {assocs!r}"
    )
    assoc = assocs[0]
    assert assoc["associationId"] == assoc_id, (
        f"expected Ref Assoc to be the association's own id {assoc['associationId']!r}, "
        f"got {assoc_id!r}"
    )
    assert assoc["associationState"] == "associated", (
        f"expected associationState 'associated', Direct Connect reports "
        f"{assoc['associationState']!r}"
    )
    assert assoc["associatedGateway"]["id"] == vgw_id, (
        f"expected the associated gateway id to be {vgw_id!r}, Direct Connect reports "
        f"{assoc['associatedGateway']['id']!r}"
    )
    assert assoc["allowedPrefixesToDirectConnectGateway"] == [{"cidr": _VPC_CIDR}], (
        f"expected the allowed prefix to be the VPN gateway's VPC CIDR {_VPC_CIDR!r}, Direct "
        f"Connect reports {assoc['allowedPrefixesToDirectConnectGateway']!r}"
    )

    delete_stack(cfn, stack_id)

    after = _poll_state(lambda: len(dc.describe_direct_connect_gateway_associations(
        directConnectGatewayId=dgw_id, associatedGatewayId=vgw_id
    )["directConnectGatewayAssociations"]), 0)
    assert after == 0, (
        f"expected no association between {dgw_id!r} and {vgw_id!r} after the stack delete, "
        f"Direct Connect still lists {after}"
    )

    gw_after = _poll_state(lambda: _gateway_state(dc, dgw_id), "deleted")
    assert gw_after == "deleted", (
        f"expected the deleted gateway's state to be 'deleted', Direct Connect reports "
        f"{gw_after!r}"
    )

    vgws = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"]
    assert [v["State"] for v in vgws] == ["deleted"], (
        f"expected the deleted VPN gateway's State to be 'deleted', EC2 reports {vgws!r}"
    )

    vpc_gone = ("InvalidVpcID.NotFound", f"The vpc ID '{vpc_id}' does not exist")
    expect_error(lambda: ec2.describe_vpcs(VpcIds=[vpc_id]), *vpc_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
