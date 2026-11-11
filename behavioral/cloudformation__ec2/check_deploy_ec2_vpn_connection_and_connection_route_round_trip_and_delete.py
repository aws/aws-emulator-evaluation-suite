"""deploy-ec2-vpn-connection-and-connection-route-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-ec2-vpn-connection-and-connection-route-round-trip-and-delete"
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

_CGW_IP = "203.0.113.42"  # TEST-NET-3, RFC 5737 documented example range
_CGW_ASN = 65002
_ROUTE_CIDR = "192.0.2.0/24"  # TEST-NET-1, RFC 5737 documented example range
# A VPN connection takes minutes to reach available; with the 300 s update and the 600 s in-check
# delete the check stays under 1800 s.
_CREATE_WAIT_S = 870.0


def _template(with_route: bool) -> str:
    resources = {
        "Cgw": {"Type": "AWS::EC2::CustomerGateway", "Properties": {
            "Type": "ipsec.1", "IpAddress": _CGW_IP, "BgpAsn": _CGW_ASN,
        }},
        "Vgw": {"Type": "AWS::EC2::VPNGateway", "Properties": {"Type": "ipsec.1"}},
        "Conn": {"Type": "AWS::EC2::VPNConnection", "Properties": {
            "Type": "ipsec.1", "CustomerGatewayId": {"Ref": "Cgw"}, "VpnGatewayId": {"Ref": "Vgw"},
            "StaticRoutesOnly": True, "Tags": [{"Key": "sim2real-vpn", "Value": "connection"}],
        }},
    }
    if with_route:
        resources["Route"] = {"Type": "AWS::EC2::VPNConnectionRoute", "Properties": {
            "VpnConnectionId": {"Ref": "Conn"}, "DestinationCidrBlock": _ROUTE_CIDR,
        }}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": {
            "CgwRef": {"Value": {"Ref": "Cgw"}},
            "VgwRef": {"Value": {"Ref": "Vgw"}},
            "ConnRef": {"Value": {"Ref": "Conn"}},
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::EC2::VPNConnection and its AWS::EC2::VPNConnectionRoute read back
    through EC2; removing the route resource moves it to the documented 'deleted' tombstone on
    the same connection, which the stack delete then does to the connection itself.
    """
    cf = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    stack = ctx.unique_name("sim2real-ec2vpnconn-")

    stack_id = create_stack(ctx, cf, stack, _template(with_route=True))
    status = wait_stack(cf, stack_id, timeout_s=_CREATE_WAIT_S)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    cgw_ref, vgw_ref, conn_ref = out["CgwRef"], out["VgwRef"], out["ConnRef"]

    # Ref against an independent read (filtered by the stack's own tag), never a read by the Ref.
    conns = ec2.describe_vpn_connections(
        Filters=[{"Name": "tag:sim2real", "Values": [stack]}]
    )["VpnConnections"]
    assert [c["VpnConnectionId"] for c in conns] == [conn_ref], (
        f"tag-filtered DescribeVpnConnections found {[c['VpnConnectionId'] for c in conns]!r} "
        f"for Ref {conn_ref!r}"
    )
    conn = conns[0]
    got = (conn["Type"], conn["CustomerGatewayId"], conn["VpnGatewayId"],
           conn["Options"]["StaticRoutesOnly"])
    assert got == ("ipsec.1", cgw_ref, vgw_ref, True), f"vpn connection reads {got!r}"

    own_tags = {t["Key"]: t["Value"] for t in conn["Tags"] if not t["Key"].startswith("aws:")}
    assert own_tags == {"sim2real": stack, "sim2real-vpn": "connection"}, f"tags {conn['Tags']!r}"
    routes = [(r["DestinationCidrBlock"], r["State"]) for r in conn["Routes"]]
    assert routes == [(_ROUTE_CIDR, "available")], f"vpn connection routes read {routes!r}"

    # Child-first: a stack update dropping the VPNConnectionRoute clears the route from the SAME
    # connection (VpnConnectionId unchanged) while the connection itself still answers.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(with_route=False))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", (
        f"route-removing update ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    after_update = ec2.describe_vpn_connections(VpnConnectionIds=[conn_ref])["VpnConnections"]
    assert after_update, f"DescribeVpnConnections({conn_ref!r}) returned nothing after the update"
    after_routes = [(r["DestinationCidrBlock"], r["State"]) for r in after_update[0]["Routes"]]
    assert after_routes == [(_ROUTE_CIDR, "deleted")], (
        f"expected the dropped route to be the documented 'deleted' tombstone on {conn_ref!r}, "
        f"got {after_routes!r}"
    )
    assert after_update[0]["VpnConnectionId"] == conn_ref, (
        f"expected the same connection {conn_ref!r} to remain, got "
        f"{after_update[0]['VpnConnectionId']!r}"
    )

    delete_stack(cf, stack_id)

    after_conn = ec2.describe_vpn_connections(VpnConnectionIds=[conn_ref])["VpnConnections"]
    assert after_conn, f"DescribeVpnConnections({conn_ref!r}) returned nothing after delete"
    assert after_conn[0]["State"] == "deleted", (
        f"expected the deleted vpn connection's State to be 'deleted', got {after_conn[0]['State']!r}"
    )

    after_cgw = ec2.describe_customer_gateways(CustomerGatewayIds=[cgw_ref])["CustomerGateways"]
    assert after_cgw and after_cgw[0]["State"] == "deleted", (
        f"expected the deleted customer gateway's State to be 'deleted', got {after_cgw!r}"
    )
    after_vgw = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_ref])["VpnGateways"]
    assert after_vgw and after_vgw[0]["State"] == "deleted", (
        f"expected the deleted vpn gateway's State to be 'deleted', got {after_vgw!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
