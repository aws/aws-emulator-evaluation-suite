"""deploy-customer-gateway-association-round-trip-and-delete."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-customer-gateway-association-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2", "networkmanager"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


# ---- Check-specific: the template, then run(). ----

# The association handler answers this while Network Manager has not yet discovered the
# customer gateway's VPN attachment on the registered transit gateway.
_NOT_YET_CONNECTED = (
    "Resource not found. (Service: NetworkManager, Status Code: 404, Request ID: <id>) "
    "(SDK Attempt Count: <n>)",
    "NotFound",
)
# RFC 5737 TEST-NET-3, reserved for documentation; never a real customer gateway.
_CGW_IP = "203.0.113.1"
_BGP_ASN = 65000  # private-use ASN range
_GN_DESC = "global network for a CloudFormation provisioning check"
_TGW_DESC = "transit gateway for a CloudFormation provisioning check"
_DEVICE_DESC = "device for a CloudFormation provisioning check"
# One deadline for the whole run under the suite's 1800 s check budget: every wait before the
# stack delete takes at most what is left once the delete (_DELETE_BUDGET_S) and the two
# settles after it (_SETTLE_S each) are set aside.
_RUN_BUDGET_S = 1740.0
_SETTLE_S = 120.0


def _template(with_association, with_vpn=True):
    resources = {
        "GlobalNetwork": {"Type": "AWS::NetworkManager::GlobalNetwork",
                          "Properties": {"Description": _GN_DESC}},
        "Tgw": {"Type": "AWS::EC2::TransitGateway", "Properties": {"Description": _TGW_DESC}},
        "TgwRegistration": {"Type": "AWS::NetworkManager::TransitGatewayRegistration",
                            "Properties": {
            "GlobalNetworkId": {"Ref": "GlobalNetwork"},
            "TransitGatewayArn": {"Fn::GetAtt": ["Tgw", "TransitGatewayArn"]},
        }},
        "Cgw": {"Type": "AWS::EC2::CustomerGateway", "Properties": {
            "Type": "ipsec.1", "BgpAsn": _BGP_ASN, "IpAddress": _CGW_IP}},
        "VpnConn": {"Type": "AWS::EC2::VPNConnection", "Properties": {
            "Type": "ipsec.1", "CustomerGatewayId": {"Ref": "Cgw"},
            "TransitGatewayId": {"Ref": "Tgw"}}},
        "Device": {"Type": "AWS::NetworkManager::Device", "Properties": {
            "GlobalNetworkId": {"Ref": "GlobalNetwork"}, "Description": _DEVICE_DESC}},
    }
    outputs = {
        "GlobalNetworkId": {"Value": {"Ref": "GlobalNetwork"}},
        "GlobalNetworkArn": {"Value": {"Fn::GetAtt": ["GlobalNetwork", "Arn"]}},
        "TgwId": {"Value": {"Ref": "Tgw"}},
        "TgwArn": {"Value": {"Fn::GetAtt": ["Tgw", "TransitGatewayArn"]}},
        "CgwId": {"Value": {"Ref": "Cgw"}},
        "VpnConnId": {"Value": {"Ref": "VpnConn"}},
        "DeviceId": {"Value": {"Fn::GetAtt": ["Device", "DeviceId"]}},
        "DeviceArn": {"Value": {"Fn::GetAtt": ["Device", "DeviceArn"]}},
    }
    if not with_vpn:
        del resources["VpnConn"], outputs["VpnConnId"]
    if with_association:
        resources["CgwAssoc"] = {
            "Type": "AWS::NetworkManager::CustomerGatewayAssociation",
            "DependsOn": ["TgwRegistration", "VpnConn"],
            "Properties": {
                "GlobalNetworkId": {"Ref": "GlobalNetwork"},
                "CustomerGatewayArn": {"Fn::Sub": "arn:${AWS::Partition}:ec2:${AWS::Region}:"
                                                  "${AWS::AccountId}:customer-gateway/${Cgw}"},
                "DeviceId": {"Fn::GetAtt": ["Device", "DeviceId"]},
            },
        }
        outputs["CgwAssocRef"] = {"Value": {"Ref": "CgwAssoc"}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _left(deadline):
    """Seconds until ``deadline`` (a time.monotonic() value)."""
    return deadline - time.monotonic()


def _settle(read, want, timeout_s=_SETTLE_S):
    """Poll ``read()`` every 2 s until it equals ``want`` or the deadline; return the last value."""
    deadline = time.monotonic() + timeout_s
    while True:
        value = read()
        if value == want or time.monotonic() > deadline:
            return value
        time.sleep(2)


def _add_association(ctx, cf, stack_id, deadline):
    """Update the stack to add the association, retrying only the documented discovery lag."""
    while True:
        cf.update_stack(StackName=stack_id, TemplateBody=_template(True))
        status = wait_stack(cf, stack_id, timeout_s=_left(deadline))
        if status == "UPDATE_COMPLETE":
            return
        assert status == "UPDATE_ROLLBACK_COMPLETE", f"association update ended {status!r}"
        rows = [e.get("ResourceStatusReason") for e in stack_events(cf, stack_id)
                if e["LogicalResourceId"] == "CgwAssoc" and e["ResourceStatus"] == "CREATE_FAILED"]
        got = handler_reason(rows[-1] if rows else None, ctx.account)
        assert got == _NOT_YET_CONNECTED, (
            f"association update failed with {got!r}, not the discovery lag {_NOT_YET_CONNECTED!r}"
        )
        assert _left(deadline) > 0, "customer gateway not connected before the run deadline"
        time.sleep(2)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation customer gateway association and its network read back as templated.

    Dropping the association keeps the global network; dropping the VPN connection leaves it
    'deleted', and the stack delete removes the global network and leaves the TGW 'deleted'.
    """
    cf = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    nm = ctx.client("networkmanager")
    stack = ctx.unique_name("sim2real-cfncga-")

    deadline = time.monotonic() + _RUN_BUDGET_S - _DELETE_BUDGET_S - 2 * _SETTLE_S
    # A transit gateway with a VPN takes minutes to create, so this check deploys one stack only.
    stack_id = create_stack(ctx, cf, stack, _template(False))
    status = wait_stack(cf, stack_id, timeout_s=_left(deadline))
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    partition = stack_id.split(":")[1]
    gn_id, tgw_id, cgw_id, device_id = (out[k] for k in ("GlobalNetworkId", "TgwId", "CgwId",
                                                         "DeviceId"))
    cgw_arn = f"arn:{partition}:ec2:{ctx.region}:{ctx.account}:customer-gateway/{cgw_id}"
    tag_filter = [{"Name": "tag:sim2real", "Values": [stack]}]

    # Each Ref against an independent read: a full listing or a listing by the stack's tag.
    gns = [g for g in paginate(nm, "describe_global_networks", "GlobalNetworks")
           if g["GlobalNetworkId"] == gn_id]
    got_gn = [(g["GlobalNetworkArn"], g["Description"], g["State"]) for g in gns]
    assert got_gn == [(out["GlobalNetworkArn"], _GN_DESC, "AVAILABLE")], f"global network {gns!r}"

    tgws = paginate(ec2, "describe_transit_gateways", "TransitGateways", Filters=tag_filter)
    got_tgw = [(t["TransitGatewayId"], t["TransitGatewayArn"], t["Description"], t["State"])
               for t in tgws]
    assert got_tgw == [(tgw_id, out["TgwArn"], _TGW_DESC, "available")], f"tgws {tgws!r}"

    regs = paginate(nm, "get_transit_gateway_registrations", "TransitGatewayRegistrations",
                    GlobalNetworkId=gn_id)
    got_regs = [(r["TransitGatewayArn"], r["State"]["Code"]) for r in regs]
    assert got_regs == [(out["TgwArn"], "AVAILABLE")], f"registrations {regs!r}"

    cgws = ec2.describe_customer_gateways(Filters=tag_filter)["CustomerGateways"]
    got_cgw = [(c["CustomerGatewayId"], c["IpAddress"], c["BgpAsn"], c["Type"], c["State"])
               for c in cgws]
    assert got_cgw == [(cgw_id, _CGW_IP, str(_BGP_ASN), "ipsec.1", "available")], f"cgw {cgws!r}"

    vpns = ec2.describe_vpn_connections(Filters=tag_filter)["VpnConnections"]
    got_vpn = [(v["VpnConnectionId"], v["CustomerGatewayId"], v["TransitGatewayId"], v["Type"],
                v["State"]) for v in vpns]
    assert got_vpn == [(out["VpnConnId"], cgw_id, tgw_id, "ipsec.1", "available")], (
        f"vpn connections {vpns!r}"
    )

    devices = paginate(nm, "get_devices", "Devices", GlobalNetworkId=gn_id)
    got_dev = [(d["DeviceId"], d["DeviceArn"], d["Description"], d["State"]) for d in devices]
    assert got_dev == [(device_id, out["DeviceArn"], _DEVICE_DESC, "AVAILABLE")], (
        f"devices {devices!r}"
    )

    def own_associations():
        return [(a["GlobalNetworkId"], a["CustomerGatewayArn"], a["DeviceId"], a["State"])
                for a in paginate(nm, "get_customer_gateway_associations",
                                  "CustomerGatewayAssociations", GlobalNetworkId=gn_id)]

    _add_association(ctx, cf, stack_id, deadline)
    ref = stack_outputs(cf, stack_id)["CgwAssocRef"]
    assert ref == f"{gn_id}|{cgw_arn}", f"Ref {ref!r}, expected {gn_id}|{cgw_arn}"
    want = [(gn_id, cgw_arn, device_id, "AVAILABLE")]
    got = _settle(own_associations, want, min(_SETTLE_S, _left(deadline)))
    assert got == want, f"associations {got!r}"

    # The child alone: an update dropping it empties the global network's associations.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(False))
    status = wait_stack(cf, stack_id, timeout_s=_left(deadline))
    assert status == "UPDATE_COMPLETE", f"association-removing update ended {status!r}"
    assert own_associations() == [], f"the dropped association is listed: {own_associations()!r}"
    still = [g["State"] for g in paginate(nm, "describe_global_networks", "GlobalNetworks",
                                          GlobalNetworkIds=[gn_id])]
    assert still == ["AVAILABLE"], f"global network after the update reads {still!r}"

    # The VPN connection before the transit gateway: EC2 refuses to delete a transit gateway while
    # its VPN attachment is still deleting, which outlasts the VPN connection's own delete.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(False, with_vpn=False))
    status = wait_stack(cf, stack_id, timeout_s=_left(deadline))
    assert status == "UPDATE_COMPLETE", f"VPN-connection-removing update ended {status!r}"
    vpn_state = _settle(lambda: [v["State"] for v in ec2.describe_vpn_connections(
        VpnConnectionIds=[out["VpnConnId"]])["VpnConnections"]], ["deleted"],
        min(_SETTLE_S, _left(deadline)))
    assert vpn_state == ["deleted"], f"VPN connection after the update reads {vpn_state!r}"
    attachment_filter = [{"Name": "transit-gateway-id", "Values": [tgw_id]},
                         {"Name": "resource-type", "Values": ["vpn"]}]
    live = _settle(lambda: [a["State"] for a in paginate(
        ec2, "describe_transit_gateway_attachments", "TransitGatewayAttachments",
        Filters=attachment_filter) if a["State"] != "deleted"], [], _left(deadline))
    assert live == [], f"the transit gateway's VPN attachment still reads {live!r}"

    delete_stack(cf, stack_id)
    gone = _settle(lambda: [g["State"] for g in paginate(
        nm, "describe_global_networks", "GlobalNetworks", GlobalNetworkIds=[gn_id])], [])
    assert gone == [], f"global network after the stack delete reads {gone!r}"
    tgw_state = _settle(lambda: [t["State"] for t in ec2.describe_transit_gateways(
        TransitGatewayIds=[tgw_id])["TransitGateways"]], ["deleted"])
    assert tgw_state == ["deleted"], f"transit gateway after the stack delete reads {tgw_state!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
