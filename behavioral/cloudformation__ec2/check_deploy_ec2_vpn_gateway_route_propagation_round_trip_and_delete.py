"""deploy-ec2-vpn-gateway-route-propagation-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-vpn-gateway-route-propagation-round-trip-and-delete"
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

_VPC_CIDR = "10.72.0.0/16"


def _template(with_propagation: bool) -> str:
    resources = {
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR}},
        "RouteTable": {"Type": "AWS::EC2::RouteTable", "Properties": {"VpcId": {"Ref": "Vpc"}}},
        "Vgw": {"Type": "AWS::EC2::VPNGateway", "Properties": {"Type": "ipsec.1"}},
        "Attachment": {"Type": "AWS::EC2::VPCGatewayAttachment", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "VpnGatewayId": {"Ref": "Vgw"},
        }},
    }
    if with_propagation:
        resources["Propagation"] = {
            "Type": "AWS::EC2::VPNGatewayRoutePropagation",
            "Properties": {"RouteTableIds": [{"Ref": "RouteTable"}], "VpnGatewayId": {"Ref": "Vgw"}},
            "DependsOn": "Attachment",
        }
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": {
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "RouteTableId": {"Value": {"Ref": "RouteTable"}},
            "VgwRef": {"Value": {"Ref": "Vgw"}},
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::EC2::VPNGatewayRoutePropagation enables route propagation from the
    declared VPN gateway onto the declared route table in EC2's own DescribeRouteTables;
    removing it disables propagation on the same table while the table and gateway still answer.
    """
    cf = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    stack = ctx.unique_name("sim2real-ec2vgwprop-")

    stack_id = create_stack(ctx, cf, stack, _template(with_propagation=True))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    vpc_id, rt_id, vgw_ref = out["VpcId"], out["RouteTableId"], out["VgwRef"]

    # Independent read: the route table by its own id (not derived from the propagation's Ref),
    # since AWS::EC2::VPNGatewayRoutePropagation has no AWS-side identity of its own.
    rts = paginate(ec2, "describe_route_tables", "RouteTables",
                   Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                            {"Name": "tag:sim2real", "Values": [stack]}])
    assert [r["RouteTableId"] for r in rts] == [rt_id], f"route tables by stack tag {rts!r}"
    # DescribeVpnGateways is not a pageable operation.
    vgws = ec2.describe_vpn_gateways(
        Filters=[{"Name": "tag:sim2real", "Values": [stack]}])["VpnGateways"]
    got = [(g["VpnGatewayId"], g["Type"], g["State"],
            [(a["VpcId"], a["State"]) for a in g["VpcAttachments"]]) for g in vgws]
    assert got == [(vgw_ref, "ipsec.1", "available", [(vpc_id, "attached")])], f"gateways {got!r}"
    propagating = [p["GatewayId"] for p in rts[0]["PropagatingVgws"]]
    assert propagating == [vgw_ref], (
        f"expected PropagatingVgws == [{vgw_ref!r}] on {rt_id!r}, got {propagating!r}"
    )

    # Child-first: a stack update dropping the propagation resource disables it on the SAME
    # route table while the table and the gateway both still answer.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(with_propagation=False))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", (
        f"propagation-removing update ended {status!r}: "
        f"{decisive_rows(stack_events(cf, stack_id))!r}"
    )
    after_rts = ec2.describe_route_tables(RouteTableIds=[rt_id])["RouteTables"]
    assert after_rts, f"DescribeRouteTables({rt_id!r}) returned nothing after the update"
    after_propagating = [p["GatewayId"] for p in after_rts[0]["PropagatingVgws"]]
    assert after_propagating == [], (
        f"expected no PropagatingVgws on {rt_id!r} after removing the propagation, "
        f"got {after_propagating!r}"
    )
    still_vgws = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_ref])["VpnGateways"]
    assert still_vgws and still_vgws[0]["State"] == "available", (
        f"expected the gateway {vgw_ref!r} to still be available, got {still_vgws!r}"
    )

    delete_stack(cf, stack_id)

    refused = ("InvalidRouteTableID.NotFound", f"The routeTable ID '{rt_id}' does not exist")
    expect_error(lambda: ec2.describe_route_tables(RouteTableIds=[rt_id]), *refused)

    after_vgw = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_ref])["VpnGateways"]
    assert after_vgw and after_vgw[0]["State"] == "deleted", (
        f"expected the deleted vpn gateway's State to be 'deleted', got {after_vgw!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
