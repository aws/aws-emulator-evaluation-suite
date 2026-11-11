"""route-server-peer-lifecycle-transitions."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "route-server-peer-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRouteServerPeer moves the peer pending->available and its routing database becomes
    queryable; DeleteRouteServerPeer removes it from the active set, and a further delete on the
    dead identifier is rejected."""
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    name = ctx.unique_name("sim2real-rsp-")

    vpc = ec2.create_vpc(
        CidrBlock="10.233.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))

    subnet = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.233.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]
    subnet_id = subnet["SubnetId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))

    rs_id = ec2.create_route_server(
        AmazonSideAsn=64512,
        PersistRoutes="disable",
        TagSpecifications=[{"ResourceType": "route-server", "Tags": [{"Key": "Name", "Value": name}]}],
    )["RouteServer"]["RouteServerId"]
    # ONE consolidated, WAITING teardown (see _teardown_route_server): per-resource
    # ctx.on_cleanup calls that fire delete_route_server_endpoint / disassociate_route_server /
    # delete_route_server without waiting for the previous async delete to actually finish race
    # the real dependency chain (peer blocks endpoint; endpoint's ENI blocks disassociate/
    # subnet/vpc; association blocks delete_route_server) and strand a billed-hourly route
    # server plus an ENI pinning a VPC slot.
    ctx.on_cleanup(lambda: _teardown_route_server(ec2, rs_id))
    _poll_until(
        lambda: ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"][0],
        lambda r: r["State"] == "available",
        timeout_s=180,
    )

    # A route server endpoint can only be created in a subnet whose VPC is
    # already associated with the route server.
    ec2.associate_route_server(RouteServerId=rs_id, VpcId=vpc_id)
    _poll_until(
        lambda: next(
            (a for a in _get_associations_safe(ec2, rs_id) if a["VpcId"] == vpc_id),
            None,
        ),
        lambda a: a is not None and a["State"] == "associated",
        timeout_s=180,
    )

    ep_id = ec2.create_route_server_endpoint(
        RouteServerId=rs_id,
        SubnetId=subnet_id,
        TagSpecifications=[
            {"ResourceType": "route-server-endpoint", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["RouteServerEndpoint"]["RouteServerEndpointId"]
    _poll_until(
        lambda: ec2.describe_route_server_endpoints(RouteServerEndpointIds=[ep_id])[
            "RouteServerEndpoints"
        ][0],
        lambda e: e["State"] == "available",
        timeout_s=240,
    )

    peer = ec2.create_route_server_peer(
        RouteServerEndpointId=ep_id,
        PeerAddress="10.233.1.10",
        BgpOptions={"PeerAsn": 65010},
        TagSpecifications=[
            {"ResourceType": "route-server-peer", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["RouteServerPeer"]
    peer_id = peer["RouteServerPeerId"]
    assert peer["PeerAddress"] == "10.233.1.10", f"expected echoed PeerAddress 10.233.1.10, got {peer['PeerAddress']!r}"
    assert peer["BgpOptions"]["PeerAsn"] == 65010, f"expected echoed PeerAsn 65010, got {peer['BgpOptions']['PeerAsn']!r}"

    peer = _poll_until(
        lambda: ec2.describe_route_server_peers(RouteServerPeerIds=[peer_id])[
            "RouteServerPeers"
        ][0],
        lambda p: p["State"] == "available",
        timeout_s=240,
    )
    assert peer["State"] == "available", f"expected peer to settle in 'available', last independently-read state was {peer['State']!r}"

    # No real BGP device is behind the peer address, so the FIB/RIB is empty -- but the
    # routing database query itself must succeed and be well-formed. Routes has no
    # smithy `required` trait: AWS may omit it entirely rather than send an empty list,
    # so a hard subscript would raise on a compliant response; the [] default is the
    # correct expected value here, not a false pass, because no BGP session was ever
    # established to learn a route from.
    rdb = ec2.get_route_server_routing_database(RouteServerId=rs_id)
    assert rdb.get("Routes", []) == [], f"expected no learned routes without a live BGP peer, got {rdb.get('Routes')!r}"
    assert rdb["AreRoutesPersisted"] is False, f"expected AreRoutesPersisted False (PersistRoutes='disable'), got {rdb['AreRoutesPersisted']!r}"

    ec2.delete_route_server_peer(RouteServerPeerId=peer_id)
    final = _poll_until(
        lambda: ec2.describe_route_server_peers(RouteServerPeerIds=[peer_id])[
            "RouteServerPeers"
        ],
        lambda lst: lst == [] or lst[0]["State"] == "deleted",
        timeout_s=240,
    )
    assert final == [] or final[0]["State"] == "deleted", f"expected the peer gone or 'deleted' after delete, independent read returned {final!r}"

    # The identifier is now dead: a further delete on it must be rejected, not silently
    # accepted a second time. Real AWS keeps the peer object around in "deleted" state
    # rather than dropping it outright, so the rejection is
    # IncorrectState, not a NotFound-class code.
    err = _error(lambda: ec2.delete_route_server_peer(RouteServerPeerId=peer_id))
    assert err["Code"] == "IncorrectState", f"expected IncorrectState, got {err!r}"
    assert err.get("Message") == f"Route Server Peer {peer_id} is in an invalid state.", (
        f"unexpected message: {err.get('Message')!r}"
    )


# ===== helpers =====
def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidNetworkInterfaceID.NotFound":
            raise


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError("expected a ClientError, call succeeded")


def _get_associations_safe(ec2, rs_id):
    """GetRouteServerAssociations raises InvalidRouteServerId.NotAssociated
    (rather than returning an empty list) while the route server has no
    established associations yet -- normalize that to an empty list so
    callers can poll uniformly."""
    from botocore.exceptions import ClientError

    try:
        return ec2.get_route_server_associations(RouteServerId=rs_id)[
            "RouteServerAssociations"
        ]
    except ClientError as err:
        if err.response["Error"]["Code"] == "InvalidRouteServerId.NotAssociated":
            return []
        raise


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


# ===== route-server teardown (self-contained) =====
# Route-server deletes are ASYNC and strictly ordered: peers block their endpoint, an
# endpoint's in-use ENI blocks DisassociateRouteServer (and DeleteSubnet/DeleteVpc), and an
# association blocks DeleteRouteServer. So the teardown retries whole passes under one shared
# budget instead of walking the chain once -- a single pass strands everything downstream of
# the first step that is still settling, and _rs_call swallows the rejection, so the leak is
# silent.
_RS_TEARDOWN_BUDGET_S = 480.0
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
    for. Filtering them out here is exactly what stranded route servers before -- discovery saw
    "nothing left to delete", skipped the wait, and DeleteRouteServerEndpoint was then rejected
    because the peer was still going away.
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
    matter how far the check got before failing. A route server is billed hourly and its
    endpoint ENI holds a VPC against the default per-Region VPC quota, so a leak here costs
    money and can block later VPC creation.
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
        live = [
            r
            for r in _rs_call(
                ec2.describe_route_servers, RouteServerIds=[route_server_id]
            ).get("RouteServers", [])
            if r.get("State") not in ("deleted", "deleting")
        ]
        if not live:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"route server {route_server_id} still {live!r} after {_RS_TEARDOWN_BUDGET_S}s of teardown"
            )
        # Guard against a zero-delay spin: if the route server is stuck refusing delete with
        # nothing left to wait on, every _rs_wait above returns instantly, so pause before the
        # next pass to avoid hammering the EC2 API into throttling.
        time.sleep(min(2.0, max(0.0, deadline - time.monotonic())))


# Network teardown: an async delete's AWS-managed ENIs hold the subnet / security group / VPC in
# DependencyViolation, so wait for them to go and retry DependencyViolation to one deadline shared by
# all network deletes (with the route-server teardown, within the suite cleanup budget), then raise.
_NET_TEARDOWN_S = 390.0
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
