"""deploy-cfn-ec2-transit-gateway-attachments-association-propagation-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-ec2-transit-gateway-attachments-association-propagation-round-trip-and-delete"
GROUP = "deploy"
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


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


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

_VPC_A_CIDR = "10.80.0.0/24"
_VPC_B_CIDR = "10.81.0.0/24"


def _template(name, az, with_assoc_and_prop):
    resources = {
        "Tgw": {"Type": "AWS::EC2::TransitGateway", "Properties": {
            "Description": name,
            "DefaultRouteTableAssociation": "disable",
            "DefaultRouteTablePropagation": "disable",
            "Tags": [{"Key": "sim2real-tgw", "Value": name}],
        }},
        "VpcA": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_A_CIDR}},
        "SubnetA": {"Type": "AWS::EC2::Subnet", "Properties": {
            "VpcId": {"Ref": "VpcA"}, "CidrBlock": _VPC_A_CIDR, "AvailabilityZone": az,
        }},
        # AWS::EC2::TransitGatewayVpcAttachment: the current, documented VPC attachment type.
        "AttachmentA": {"Type": "AWS::EC2::TransitGatewayVpcAttachment", "Properties": {
            "TransitGatewayId": {"Ref": "Tgw"}, "VpcId": {"Ref": "VpcA"},
            "SubnetIds": [{"Ref": "SubnetA"}],
        }},
        "VpcB": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_B_CIDR}},
        "SubnetB": {"Type": "AWS::EC2::Subnet", "Properties": {
            "VpcId": {"Ref": "VpcB"}, "CidrBlock": _VPC_B_CIDR, "AvailabilityZone": az,
        }},
        # AWS::EC2::TransitGatewayAttachment: a second, separately registered CFN type for the
        # same underlying VPC attachment.
        "AttachmentB": {"Type": "AWS::EC2::TransitGatewayAttachment", "Properties": {
            "TransitGatewayId": {"Ref": "Tgw"}, "VpcId": {"Ref": "VpcB"},
            "SubnetIds": [{"Ref": "SubnetB"}],
        }},
        "RouteTable": {"Type": "AWS::EC2::TransitGatewayRouteTable", "Properties": {
            "TransitGatewayId": {"Ref": "Tgw"},
        }},
    }
    outputs = {k: {"Value": {"Ref": k}} for k in
               ("Tgw", "VpcA", "SubnetA", "AttachmentA", "VpcB", "SubnetB", "AttachmentB",
                "RouteTable")}
    if with_assoc_and_prop:
        resources["Association"] = {
            "Type": "AWS::EC2::TransitGatewayRouteTableAssociation",
            "Properties": {"TransitGatewayRouteTableId": {"Ref": "RouteTable"},
                           "TransitGatewayAttachmentId": {"Ref": "AttachmentA"}},
        }
        resources["Propagation"] = {
            "Type": "AWS::EC2::TransitGatewayRouteTablePropagation",
            "Properties": {"TransitGatewayRouteTableId": {"Ref": "RouteTable"},
                           "TransitGatewayAttachmentId": {"Ref": "AttachmentB"}},
        }
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _usable_az(ec2):
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert usable, "no available Availability Zone in this region"
    return usable[0]


def _own_tags(resource):
    return {t["Key"]: t["Value"] for t in resource.get("Tags", [])
            if not t["Key"].startswith("aws:")}


def _wired(ec2, rt_id):
    """``(associated, propagated)`` attachment ids of the route table, every page read."""
    assoc = paginate(ec2, "get_transit_gateway_route_table_associations", "Associations",
                     TransitGatewayRouteTableId=rt_id)
    props = paginate(ec2, "get_transit_gateway_route_table_propagations",
                     "TransitGatewayRouteTablePropagations", TransitGatewayRouteTableId=rt_id)
    return ([(a["TransitGatewayAttachmentId"], a["State"]) for a in assoc],
            [(p["TransitGatewayAttachmentId"], p["State"]) for p in props])


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """CloudFormation's two TGW VPC attachment types and a route-table association and
    propagation read back through EC2 by independent reads; an update dropping the wiring
    removes it while the attachments stay, and the stack delete removes the rest.
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-tgwatt-")
    az = _usable_az(ec2)

    stack_id = create_stack(ctx, cfn, stack, _template(stack, az, True))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    tag_filter = [{"Name": "tag:sim2real", "Values": [stack]}]

    tgws = paginate(ec2, "describe_transit_gateways", "TransitGateways", Filters=tag_filter)
    got = [(g["TransitGatewayId"], g["State"], g["Description"], _own_tags(g),
            g["Options"]["DefaultRouteTableAssociation"],
            g["Options"]["DefaultRouteTablePropagation"]) for g in tgws]
    assert got == [(out["Tgw"], "available", stack, {"sim2real": stack, "sim2real-tgw": stack},
                    "disable", "disable")], f"DescribeTransitGateways by stack tag {got!r}"

    attachments = paginate(ec2, "describe_transit_gateway_vpc_attachments",
                           "TransitGatewayVpcAttachments",
                           Filters=[{"Name": "transit-gateway-id", "Values": [out["Tgw"]]}])
    got = sorted((a["TransitGatewayAttachmentId"], a["State"], a["VpcId"], a["SubnetIds"],
                  _own_tags(a)) for a in attachments)
    want = sorted([(out["AttachmentA"], "available", out["VpcA"], [out["SubnetA"]],
                    {"sim2real": stack}),
                   (out["AttachmentB"], "available", out["VpcB"], [out["SubnetB"]],
                    {"sim2real": stack})])
    assert got == want, f"attachments of {out['Tgw']!r}: {got!r}, expected {want!r}"

    rts = paginate(ec2, "describe_transit_gateway_route_tables", "TransitGatewayRouteTables",
                   Filters=[{"Name": "transit-gateway-id", "Values": [out["Tgw"]]}])
    got = [(r["TransitGatewayRouteTableId"], r["State"]) for r in rts]
    assert got == [(out["RouteTable"], "available")], f"route tables of the gateway {got!r}"
    rt_id = out["RouteTable"]
    assert _wired(ec2, rt_id) == ([(out["AttachmentA"], "associated")],
                                  [(out["AttachmentB"], "enabled")]), (
        f"route table wiring {_wired(ec2, rt_id)!r}"
    )

    # The association's and propagation's own delete, while the attachments and table remain.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(stack, az, False))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "UPDATE_COMPLETE", f"wiring-removing update ended {status!r}"
    assert _wired(ec2, rt_id) == ([], []), f"route table wiring after the update {_wired(ec2, rt_id)!r}"
    still = paginate(ec2, "describe_transit_gateway_vpc_attachments",
                     "TransitGatewayVpcAttachments",
                     TransitGatewayAttachmentIds=[out["AttachmentA"], out["AttachmentB"]])
    assert sorted(a["State"] for a in still) == ["available", "available"], f"attachments {still!r}"

    delete_stack(cfn, stack_id)
    # Deleted gateways and attachments stay describable for a while in State "deleted".
    after = paginate(ec2, "describe_transit_gateways", "TransitGateways",
                     TransitGatewayIds=[out["Tgw"]])
    assert [g["State"] for g in after] == ["deleted"], f"gateway after the delete {after!r}"
    after = paginate(ec2, "describe_transit_gateway_vpc_attachments",
                     "TransitGatewayVpcAttachments",
                     TransitGatewayAttachmentIds=[out["AttachmentA"], out["AttachmentB"]])
    assert sorted(a["State"] for a in after) == ["deleted", "deleted"], f"attachments {after!r}"
    refused = (
        "InvalidRouteTableID.NotFound",
        f"Transit Gateway Route Table {rt_id} was deleted or does not exist.",
    )
    expect_error(
        lambda: ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[rt_id]),
        *refused,
    )
    for vpc in (out["VpcA"], out["VpcB"]):
        refused = ("InvalidVpcID.NotFound", f"The vpc ID '{vpc}' does not exist")
        expect_error(lambda vpc=vpc: ec2.describe_vpcs(VpcIds=[vpc]), *refused)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
