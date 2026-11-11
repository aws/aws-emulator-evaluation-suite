"""deploy-ec2-customer-gateway-and-vpn-gateway-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-ec2-customer-gateway-and-vpn-gateway-round-trip-and-delete"
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


# ---- Check-specific: the template, then run(). ----

_CGW_IP = "203.0.113.17"  # TEST-NET-3, RFC 5737 documented example range
_CGW_ASN = 65000
_VGW_ASN = 65001


def _template(name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Cgw": {"Type": "AWS::EC2::CustomerGateway", "Properties": {
                "Type": "ipsec.1", "IpAddress": _CGW_IP, "BgpAsn": _CGW_ASN,
                "Tags": [{"Key": "sim2real-cgw", "Value": name}],
            }},
            "Vgw": {"Type": "AWS::EC2::VPNGateway", "Properties": {
                "Type": "ipsec.1", "AmazonSideAsn": _VGW_ASN,
                "Tags": [{"Key": "sim2real-vgw", "Value": name}],
            }},
        },
        "Outputs": {
            "CgwRef": {"Value": {"Ref": "Cgw"}},
            "VgwRef": {"Value": {"Ref": "Vgw"}},
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::EC2::CustomerGateway and AWS::EC2::VPNGateway read back through EC2
    with their templated properties and tags, and deleting the stack moves both to the documented
    'deleted' tombstone state rather than a NotFound.
    """
    cf = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    stack = ctx.unique_name("sim2real-ec2cgwvgw-")

    stack_id = create_stack(ctx, cf, stack, _template(stack))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    cgw_ref, vgw_ref = out["CgwRef"], out["VgwRef"]

    # Ref against an independent read (filtered by the stack's own tag), never a read by the Ref.
    # Neither DescribeCustomerGateways nor DescribeVpnGateways is a pageable operation.
    cgws = ec2.describe_customer_gateways(
        Filters=[{"Name": "tag:sim2real", "Values": [stack]}]
    )["CustomerGateways"]
    assert [c["CustomerGatewayId"] for c in cgws] == [cgw_ref], (
        f"tag-filtered DescribeCustomerGateways found {[c['CustomerGatewayId'] for c in cgws]!r} "
        f"for Ref {cgw_ref!r}"
    )
    vgws = ec2.describe_vpn_gateways(
        Filters=[{"Name": "tag:sim2real", "Values": [stack]}]
    )["VpnGateways"]
    assert [v["VpnGatewayId"] for v in vgws] == [vgw_ref], (
        f"tag-filtered DescribeVpnGateways found {[v['VpnGatewayId'] for v in vgws]!r} "
        f"for Ref {vgw_ref!r}"
    )

    cgw, vgw = cgws[0], vgws[0]
    got_cgw = (cgw["IpAddress"], cgw["BgpAsn"], cgw["Type"], cgw["State"])
    assert got_cgw == (_CGW_IP, str(_CGW_ASN), "ipsec.1", "available"), (
        f"customer gateway reads {got_cgw!r}"
    )
    got_vgw = (vgw["Type"], vgw["AmazonSideAsn"], vgw["State"])
    assert got_vgw == ("ipsec.1", _VGW_ASN, "available"), f"vpn gateway reads {got_vgw!r}"
    got = [{t["Key"]: t["Value"] for t in g["Tags"] if not t["Key"].startswith("aws:")}
           for g in (cgw, vgw)]
    assert got == [{"sim2real": stack, "sim2real-cgw": stack},
                   {"sim2real": stack, "sim2real-vgw": stack}], f"gateway tags {got!r}"

    delete_stack(cf, stack_id)

    after_cgw = ec2.describe_customer_gateways(CustomerGatewayIds=[cgw_ref])["CustomerGateways"]
    assert after_cgw, f"DescribeCustomerGateways({cgw_ref!r}) returned nothing after delete"
    assert after_cgw[0]["State"] == "deleted", (
        f"expected the deleted customer gateway's State to be 'deleted', got {after_cgw[0]['State']!r}"
    )

    after_vgw = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_ref])["VpnGateways"]
    assert after_vgw, f"DescribeVpnGateways({vgw_ref!r}) returned nothing after delete"
    assert after_vgw[0]["State"] == "deleted", (
        f"expected the deleted vpn gateway's State to be 'deleted', got {after_vgw[0]['State']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
