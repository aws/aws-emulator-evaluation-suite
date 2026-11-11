"""op-contract-create-route-server-peer."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-create-route-server-peer"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRouteServerPeer: success creates a BGP peer on an available endpoint of a route
    server that has been associated with the VPC; a nonexistent RouteServerEndpointId is
    rejected."""
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-rs-peer-contract-")
    tag_spec = lambda resource_type: [  # noqa: E731
        {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}
    ]

    vpc_id = ec2.create_vpc(CidrBlock="10.79.0.0/16", TagSpecifications=tag_spec("vpc"))["Vpc"][
        "VpcId"
    ]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.79.1.0/24", TagSpecifications=tag_spec("subnet")
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    rs_id = ec2.create_route_server(
        AmazonSideAsn=64512, TagSpecifications=tag_spec("route-server")
    )["RouteServer"]["RouteServerId"]
    # ONE consolidated, WAITING teardown (see _teardown_route_server):
    # the per-resource cleanups this replaces did not wait for the
    # previous async delete, so every one of them failed in turn.
    ctx.on_cleanup(lambda: _teardown_route_server(ec2, rs_id))
    _poll_until(
        lambda: ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"][0]["State"],
        lambda s: s == "available",
        timeout_s=90.0,
        interval_s=3.0,
        description="route server reaching available",
    )

    # A route server must be associated with a VPC before an endpoint can be created for it.
    ec2.associate_route_server(RouteServerId=rs_id, VpcId=vpc_id)
    _poll_until(
        lambda: next(
            (
                a["State"]
                for a in ec2.get_route_server_associations(RouteServerId=rs_id)[
                    "RouteServerAssociations"
                ]
                if a["VpcId"] == vpc_id
            ),
            None,
        ),
        lambda s: s == "associated",
        timeout_s=90.0,
        interval_s=3.0,
        description="route server VPC association reaching associated",
    )

    endpoint_id = ec2.create_route_server_endpoint(
        RouteServerId=rs_id, SubnetId=subnet_id, TagSpecifications=tag_spec("route-server-endpoint")
    )["RouteServerEndpoint"]["RouteServerEndpointId"]
    endpoint_state = _poll_until(
        lambda: ec2.describe_route_server_endpoints(RouteServerEndpointIds=[endpoint_id])[
            "RouteServerEndpoints"
        ][0]["State"],
        lambda s: s in ("available", "failed"),
        timeout_s=180.0,
        interval_s=5.0,
        description="route server endpoint reaching a terminal state",
    )
    assert endpoint_state == "available", f"route server endpoint ended in {endpoint_state!r}"

    resp = ec2.create_route_server_peer(
        RouteServerEndpointId=endpoint_id,
        PeerAddress="10.79.1.100",
        BgpOptions={"PeerAsn": 65000},
        TagSpecifications=tag_spec("route-server-peer"),
    )
    peer = resp["RouteServerPeer"]
    peer_id = peer["RouteServerPeerId"]

    assert peer["RouteServerEndpointId"] == endpoint_id
    assert peer["BgpOptions"]["PeerAsn"] == 65000

    final_state = _poll_until(
        lambda: ec2.describe_route_server_peers(RouteServerPeerIds=[peer_id])[
            "RouteServerPeers"
        ][0]["State"],
        lambda s: s in ("available", "failed"),
        timeout_s=180.0,
        interval_s=5.0,
        description="route server peer reaching a terminal state",
    )
    assert final_state == "available", f"route server peer ended in {final_state!r}"

    # Error boundary: a nonexistent RouteServerEndpointId must be rejected. (Use a well-formed
    # 17-hex-char ID rather than all zeros, which the service treats as malformed rather than
    # not-found.)
    code, message = _error_of(
        lambda: ec2.create_route_server_peer(
            RouteServerEndpointId="rse-0123456789abcdef0",
            PeerAddress="10.79.1.101",
            BgpOptions={"PeerAsn": 65000},
        )
    )
    assert code == "InvalidRouteServerEndpointId.NotFound", (
        f"expected InvalidRouteServerEndpointId.NotFound, got {code!r}"
    )
    assert message == "The route-server-endpoint ID 'rse-0123456789abcdef0' does not exist", message


# ===== helpers =====
def _error_of(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises: accepting
    input real AWS refuses is a distinct failure from returning the wrong error code."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


# ===== route-server teardown (self-contained) =====
# Route-server deletes are ASYNC and strictly ordered: peers block their endpoint, an
# endpoint's in-use ENI blocks DisassociateRouteServer (and DeleteSubnet/DeleteVpc), and an
# association blocks DeleteRouteServer. So the teardown retries whole passes under one shared
# budget instead of walking the chain once -- a single pass strands everything downstream of
# the first step that is still settling. A route server still live at the end of the budget
# raises.
_RS_TEARDOWN_BUDGET_S = 570.0
# Terminal states, from the botocore enums: peers are pending|available|deleting|deleted|
# failing|failed, endpoints add delete-failed (also terminal -- waiting out the budget on it
# would only stall the teardown).
_RS_PEER_TERMINAL = ("deleted", "failed")
_RS_ENDPOINT_TERMINAL = ("deleted", "delete-failed", "failed")


def _rs_call(fn, **kwargs):
    """Best-effort AWS call used only during teardown, so cleanup can never mask a result."""
    try:
        return fn(**kwargs) or {}
    except Exception:  # noqa: BLE001
        return {}


def _rs_wait(remaining, *, deadline, interval_s=2.0) -> None:
    while time.monotonic() < deadline:
        if not remaining():
            return
        time.sleep(interval_s)


def _rs_peers(ec2, route_server_id):
    """Peers of this route server that still block deleting its endpoint.

    Deliberately includes peers already in "deleting": they are what the next step has to WAIT
    for. Filtering them out would strand the route server: discovery would see nothing left to
    delete, skip the wait, and DeleteRouteServerEndpoint would be refused while the peer is still
    going away.
    """
    return [
        p
        for p in _rs_call(ec2.describe_route_server_peers).get("RouteServerPeers", [])
        if p.get("RouteServerId") == route_server_id and p.get("State") not in _RS_PEER_TERMINAL
    ]


def _rs_endpoints(ec2, route_server_id):
    """Endpoints of this route server; includes "deleting" ones, for the same reason as _rs_peers."""
    return [
        e
        for e in _rs_call(ec2.describe_route_server_endpoints).get("RouteServerEndpoints", [])
        if e.get("RouteServerId") == route_server_id
        and e.get("State") not in _RS_ENDPOINT_TERMINAL
    ]


def _rs_propagations(ec2, route_server_id):
    return _rs_call(ec2.get_route_server_propagations, RouteServerId=route_server_id).get(
        "RouteServerPropagations", []
    )


def _rs_associations(ec2, route_server_id):
    """VPC associations still holding the route server.

    RouteServerAssociationState is only associating|associated|disassociating -- there is no
    terminal "disassociated"; the association DISAPPEARS from the list once the disassociation
    completes, so absence is the completion signal and "disassociating" still blocks
    DeleteRouteServer. Once the last one is gone GetRouteServerAssociations RAISES
    InvalidRouteServerId.NotAssociated instead of returning an empty list (observed against
    real AWS); _rs_call turns that into {}, which reads as "none left" -- exactly right here.
    """
    return _rs_call(ec2.get_route_server_associations, RouteServerId=route_server_id).get(
        "RouteServerAssociations", []
    )


def _teardown_route_server(ec2, route_server_id: str) -> None:
    """Delete a route server and everything hanging off it, WAITING at each step.

    Registered as ONE cleanup right after CreateRouteServer, and DISCOVERY-based rather than
    id-based, so it tears down whatever peers/endpoints/propagations/associations exist no
    matter how far the check got before failing. A route server is billed HOURLY and its
    endpoint ENI also holds a VPC against the account's per-Region VPC quota, so a silent
    leak here costs money and can exhaust that quota.
    """
    deadline = time.monotonic() + _RS_TEARDOWN_BUDGET_S
    while True:
        for peer in _rs_peers(ec2, route_server_id):
            if peer.get("State") != "deleting":
                _rs_call(ec2.delete_route_server_peer, RouteServerPeerId=peer["RouteServerPeerId"])
        _rs_wait(lambda: _rs_peers(ec2, route_server_id), deadline=deadline)

        for endpoint in _rs_endpoints(ec2, route_server_id):
            if endpoint.get("State") != "deleting":
                _rs_call(
                    ec2.delete_route_server_endpoint,
                    RouteServerEndpointId=endpoint["RouteServerEndpointId"],
                )
        _rs_wait(lambda: _rs_endpoints(ec2, route_server_id), deadline=deadline)

        for propagation in _rs_propagations(ec2, route_server_id):
            _rs_call(
                ec2.disable_route_server_propagation,
                RouteServerId=route_server_id,
                RouteTableId=propagation["RouteTableId"],
            )
        _rs_wait(lambda: _rs_propagations(ec2, route_server_id), deadline=deadline)

        for assoc in _rs_associations(ec2, route_server_id):
            if assoc.get("State") != "disassociating":
                _rs_call(
                    ec2.disassociate_route_server,
                    RouteServerId=route_server_id,
                    VpcId=assoc["VpcId"],
                )
        _rs_wait(lambda: _rs_associations(ec2, route_server_id), deadline=deadline)

        _rs_call(ec2.delete_route_server, RouteServerId=route_server_id)
        # "deleting" is good enough to stop here: the route server itself holds no ENI, so it
        # cannot block the subnet/VPC deletes that run after this cleanup.
        try:
            servers = ec2.describe_route_servers(RouteServerIds=[route_server_id])["RouteServers"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidRouteServerId.NotFound":
                return
            raise
        live = [r for r in servers if r.get("State") not in ("deleted", "deleting")]
        if not live:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"route server {route_server_id} still live after {_RS_TEARDOWN_BUDGET_S}s: {live!r}")
        # Guard against a zero-delay spin: if the route server is stuck refusing delete with
        # nothing left to wait on, every _rs_wait above returns instantly, so pause before the
        # next pass to avoid hammering the EC2 API into throttling.
        time.sleep(min(2.0, max(0.0, deadline - time.monotonic())))


# AWS-managed ENIs (endpoints, load balancers, instances) leave a VPC asynchronously after their
# owner's delete returns, so DeleteSubnet/DeleteSecurityGroup/DeleteVpc can fail with
# DependencyViolation. Wait (bounded) for the ENIs to go, retry inside the same window, and raise
# naming any ENIs still attached. Teardown-only: run() never calls this.
_NET_TEARDOWN_S = 300.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
