"""deploy-cfn-ec2-transit-gateway-route-table-and-policy-table-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-ec2-transit-gateway-route-table-and-policy-table-round-trip-and-delete"
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

_BLACKHOLE_CIDR = "203.0.113.0/24"
_ASN = 64515


def _template(name, tables=True, route=True):
    resources = {"Tgw": {"Type": "AWS::EC2::TransitGateway", "Properties": {
        "Description": name, "AmazonSideAsn": _ASN,
        "DefaultRouteTableAssociation": "disable", "DefaultRouteTablePropagation": "disable",
        "Tags": [{"Key": "sim2real-tgw", "Value": name}],
    }}}
    outputs = {"Tgw": {"Value": {"Ref": "Tgw"}}}
    if tables:
        resources["RouteTable"] = {"Type": "AWS::EC2::TransitGatewayRouteTable", "Properties": {
            "TransitGatewayId": {"Ref": "Tgw"}, "Tags": [{"Key": "sim2real-rt", "Value": name}],
        }}
        resources["PolicyTable"] = {"Type": "AWS::EC2::TransitGatewayPolicyTable", "Properties": {
            "TransitGatewayId": {"Ref": "Tgw"}, "Tags": [{"Key": "sim2real-pt", "Value": name}],
        }}
        outputs.update({"RouteTable": {"Value": {"Ref": "RouteTable"}},
                        "PolicyTable": {"Value": {"Ref": "PolicyTable"}}})
    if tables and route:
        resources["BlackholeRoute"] = {"Type": "AWS::EC2::TransitGatewayRoute", "Properties": {
            "TransitGatewayRouteTableId": {"Ref": "RouteTable"},
            "DestinationCidrBlock": _BLACKHOLE_CIDR, "Blackhole": True,
        }}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _own_tags(resource):
    return {t["Key"]: t["Value"] for t in resource.get("Tags", [])
            if not t["Key"].startswith("aws:")}


def _routes(ec2, rt_id):
    return [(r["DestinationCidrBlock"], r["Type"], r["State"]) for r in
            ec2.search_transit_gateway_routes(
                TransitGatewayRouteTableId=rt_id,
                Filters=[{"Name": "route-search.exact-match", "Values": [_BLACKHOLE_CIDR]}],
            )["Routes"]]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation TransitGateway, route table, policy table and blackhole route read back
    through EC2 by independent reads; updates drop the route, then both tables, each proven gone
    while its parent answers, and the stack delete leaves the gateway's 'deleted' tombstone.
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-tgwrt-")

    stack_id = create_stack(ctx, cfn, stack, _template(stack))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    tgw_id, rt_id, pt_id = out["Tgw"], out["RouteTable"], out["PolicyTable"]
    by_tgw = [{"Name": "transit-gateway-id", "Values": [tgw_id]}]

    tgws = paginate(ec2, "describe_transit_gateways", "TransitGateways",
                    Filters=[{"Name": "tag:sim2real", "Values": [stack]}])
    got = [(g["TransitGatewayId"], g["State"], g["Description"], g["Options"]["AmazonSideAsn"],
            _own_tags(g)) for g in tgws]
    assert got == [(tgw_id, "available", stack, _ASN,
                    {"sim2real": stack, "sim2real-tgw": stack})], f"gateways by stack tag {got!r}"
    rts = paginate(ec2, "describe_transit_gateway_route_tables", "TransitGatewayRouteTables",
                   Filters=by_tgw)
    got = [(r["TransitGatewayRouteTableId"], r["State"], _own_tags(r)) for r in rts]
    assert got == [(rt_id, "available", {"sim2real": stack, "sim2real-rt": stack})], (
        f"route tables of the gateway {got!r}"
    )
    pts = paginate(ec2, "describe_transit_gateway_policy_tables", "TransitGatewayPolicyTables",
                   Filters=by_tgw)
    got = [(t["TransitGatewayPolicyTableId"], t["State"], _own_tags(t)) for t in pts]
    assert got == [(pt_id, "available", {"sim2real": stack, "sim2real-pt": stack})], (
        f"policy tables of the gateway {got!r}"
    )
    assert _routes(ec2, rt_id) == [(_BLACKHOLE_CIDR, "static", "blackhole")], "blackhole route"

    # The route's own delete, while its route table still answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(stack, route=False))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "UPDATE_COMPLETE", f"route-removing update ended {status!r}"
    assert _routes(ec2, rt_id) == [], f"routes after the update {_routes(ec2, rt_id)!r}"

    # The tables' own delete, while the gateway still answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(stack, tables=False))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "UPDATE_COMPLETE", f"table-removing update ended {status!r}"
    refused = (
        "InvalidRouteTableID.NotFound",
        f"Transit Gateway Route Table {rt_id} was deleted or does not exist.",
    )
    expect_error(
        lambda: ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[rt_id]),
        *refused,
    )
    refused = (
        "InvalidTransitGatewayPolicyTableId.NotFound",
        f"Transit Gateway Policy Table {pt_id} was deleted or does not exist.",
    )
    expect_error(
        lambda: ec2.describe_transit_gateway_policy_tables(TransitGatewayPolicyTableIds=[pt_id]),
        *refused,
    )
    still = paginate(ec2, "describe_transit_gateways", "TransitGateways",
                     TransitGatewayIds=[tgw_id])
    assert [g["State"] for g in still] == ["available"], f"gateway after the update {still!r}"

    # A deleted gateway is a documented tombstone, not a NotFound.
    delete_stack(cfn, stack_id)
    after = paginate(ec2, "describe_transit_gateways", "TransitGateways",
                     TransitGatewayIds=[tgw_id])
    assert [g["State"] for g in after] == ["deleted"], f"gateway after the delete {after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
