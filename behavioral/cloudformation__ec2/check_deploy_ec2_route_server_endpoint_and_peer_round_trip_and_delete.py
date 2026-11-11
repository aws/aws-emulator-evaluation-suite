"""deploy-ec2-route-server-endpoint-and-peer-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-ec2-route-server-endpoint-and-peer-round-trip-and-delete"
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


_VPC_CIDR = "10.98.0.0/16"
_SUBNET_CIDR = "10.98.1.0/24"
_PEER_ADDRESS = "10.98.1.10"
_AMAZON_SIDE_ASN = 64512
_PEER_ASN = 65001


def _template(tag_value: str) -> str:
    t = [{"Key": "sim2real-res", "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR}},
            "Subnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR,
                               "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]}},
            },
            "RouteServer": {
                "Type": "AWS::EC2::RouteServer",
                "Properties": {"AmazonSideAsn": _AMAZON_SIDE_ASN, "Tags": t},
            },
            "Association": {
                "Type": "AWS::EC2::RouteServerAssociation",
                "Properties": {"RouteServerId": {"Ref": "RouteServer"}, "VpcId": {"Ref": "Vpc"}},
            },
            "Endpoint": {
                "Type": "AWS::EC2::RouteServerEndpoint",
                "DependsOn": "Association",
                "Properties": {"RouteServerId": {"Ref": "RouteServer"},
                               "SubnetId": {"Ref": "Subnet"}, "Tags": t},
            },
            "Peer": {
                "Type": "AWS::EC2::RouteServerPeer",
                "Properties": {"RouteServerEndpointId": {"Ref": "Endpoint"},
                               "PeerAddress": _PEER_ADDRESS,
                               "BgpOptions": {"PeerAsn": _PEER_ASN}, "Tags": t},
            },
        },
        "Outputs": {
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "SubnetId": {"Value": {"Ref": "Subnet"}},
            "RouteServerId": {"Value": {"Ref": "RouteServer"}},
            "EndpointId": {"Value": {"Ref": "Endpoint"}},
            "EndpointEniId": {"Value": {"Fn::GetAtt": ["Endpoint", "EniId"]}},
            "PeerId": {"Value": {"Ref": "Peer"}},
            "PeerEndpointEniId": {"Value": {"Fn::GetAtt": ["Peer", "EndpointEniId"]}},
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation route server endpoint and BGP peer read back through EC2.

    Each Ref, GetAtt, templated property and tag matches EC2; deleting the stack leaves the
    endpoint and peer in their documented 'deleted' tombstone state.
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-cfnrsep-")
    tag_value = ctx.unique_name("sim2real-cfnrsep-res-")
    tag_filter = [{"Name": "tag:sim2real-res", "Values": [tag_value]}]
    tag = {"Key": "sim2real-res", "Value": tag_value}

    stack_id = create_stack(ctx, cfn, stack, _template(tag_value))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    vpc_id, subnet_id, rs_id = out["VpcId"], out["SubnetId"], out["RouteServerId"]
    ep_id, peer_id = out["EndpointId"], out["PeerId"]

    # Endpoint: Ref == the one endpoint carrying this run's tag; GetAtt EniId == EC2's value.
    eps = paginate(ec2, "describe_route_server_endpoints", "RouteServerEndpoints",
                   Filters=tag_filter)
    assert [e["RouteServerEndpointId"] for e in eps] == [ep_id], f"tagged endpoints {eps!r}"
    ep = eps[0]
    got = (ep["RouteServerId"], ep["VpcId"], ep["SubnetId"], ep["EniId"], ep["State"],
           tag in ep.get("Tags", []))
    want = (rs_id, vpc_id, subnet_id, out["EndpointEniId"], "available", True)
    assert got == want, f"endpoint reads {got!r}, expected {want!r}"

    # Peer: Ref == the one peer carrying this run's tag; GetAtt EndpointEniId == EC2's value.
    peers = paginate(ec2, "describe_route_server_peers", "RouteServerPeers", Filters=tag_filter)
    assert [p["RouteServerPeerId"] for p in peers] == [peer_id], f"tagged peers {peers!r}"
    peer = peers[0]
    got = (peer["RouteServerEndpointId"], peer["RouteServerId"], peer["EndpointEniId"],
           peer["PeerAddress"], peer["BgpOptions"]["PeerAsn"], tag in peer.get("Tags", []))
    want = (ep_id, rs_id, out["PeerEndpointEniId"], _PEER_ADDRESS, _PEER_ASN, True)
    assert got == want, f"peer reads {got!r}, expected {want!r}"

    delete_stack(cfn, stack_id)
    # Deleted endpoints and peers keep listing in their documented tombstone state.
    states = [p["State"] for p in
              ec2.describe_route_server_peers(RouteServerPeerIds=[peer_id])["RouteServerPeers"]]
    assert states == ["deleted"], f"peer after the stack delete reads {states!r}"
    states = [e["State"] for e in ec2.describe_route_server_endpoints(
        RouteServerEndpointIds=[ep_id])["RouteServerEndpoints"]]
    assert states == ["deleted"], f"endpoint after the stack delete reads {states!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
