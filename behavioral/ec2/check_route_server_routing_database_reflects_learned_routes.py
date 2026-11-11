"""route-server-routing-database-reflects-learned-routes."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "route-server-routing-database-reflects-learned-routes"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A route server peer and route-table propagation persist the configuration written; with no BGP
    session GetRouteServerRoutingDatabase reports no routes and AreRoutesPersisted=False despite
    PersistRoutes, so a target that fabricates routes or echoes the setting fails."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-rsdb-")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.190.0.0/16", TagSpecifications=_tag_spec("vpc", name)
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    _wait_vpc_available(ec2, vpc_id)
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.190.1.0/24", TagSpecifications=_tag_spec("subnet", name)
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    route_table_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=_tag_spec("route-table", name)
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=route_table_id))

    route_server_id = ec2.create_route_server(
        AmazonSideAsn=65000,
        PersistRoutes="enable",
        PersistRoutesDuration=1,
        TagSpecifications=_tag_spec("route-server", name),
    )["RouteServer"]["RouteServerId"]
    # ONE consolidated, discovery-based, WAITING teardown: deletes are async and strictly
    # ordered (a peer blocks its endpoint, an in-use ENI blocks disassociation, an association
    # or propagation blocks DeleteRouteServer), so per-resource on_cleanup lambdas fired without
    # waiting for the previous step strand the route server -- see _teardown_route_server.
    ctx.on_cleanup(lambda: _teardown_route_server(ec2, route_server_id))
    _wait_state(ec2, "describe_route_servers", "RouteServerIds", "RouteServers", route_server_id, "available")

    # A route server must be associated with the VPC before an endpoint can be created in one
    # of its subnets -- CreateRouteServerEndpoint otherwise rejects with
    # InvalidRouteServerId.NotAssociated.
    ec2.associate_route_server(RouteServerId=route_server_id, VpcId=vpc_id)
    _wait_association(ec2, route_server_id, vpc_id, "associated")

    endpoint_id = ec2.create_route_server_endpoint(
        RouteServerId=route_server_id, SubnetId=subnet_id, TagSpecifications=_tag_spec("route-server-endpoint", name)
    )["RouteServerEndpoint"]["RouteServerEndpointId"]
    _wait_state(
        ec2, "describe_route_server_endpoints", "RouteServerEndpointIds", "RouteServerEndpoints", endpoint_id, "available"
    )

    peer_address = "10.190.1.10"
    peer = ec2.create_route_server_peer(
        RouteServerEndpointId=endpoint_id,
        PeerAddress=peer_address,
        BgpOptions={"PeerAsn": 65001},
        TagSpecifications=_tag_spec("route-server-peer", name),
    )["RouteServerPeer"]

    assert peer["RouteServerId"] == route_server_id
    assert peer["RouteServerEndpointId"] == endpoint_id
    assert peer["PeerAddress"] == peer_address
    assert peer["BgpOptions"]["PeerAsn"] == 65001
    assert peer["State"] in ("pending", "available", "failing", "failed")

    propagation = ec2.enable_route_server_propagation(RouteServerId=route_server_id, RouteTableId=route_table_id)[
        "RouteServerPropagation"
    ]
    assert propagation["RouteServerId"] == route_server_id
    assert propagation["RouteTableId"] == route_table_id
    assert propagation["State"] in ("pending", "available")

    found_propagation = _wait_propagation(ec2, route_server_id, route_table_id)
    assert found_propagation is not None, "enabled propagation is not visible in GetRouteServerPropagations"
    assert found_propagation["State"] in ("pending", "available")

    database = ec2.get_route_server_routing_database(RouteServerId=route_server_id)
    assert database["Routes"] == [], (
        "no BGP session was ever established for this route server, so the routing database must not "
        "fabricate any learned routes"
    )
    assert database["AreRoutesPersisted"] is False, (
        f"route server {route_server_id} was created with PersistRoutes='enable' but has no "
        f"learned routes to persist, so GetRouteServerRoutingDatabase must report "
        f"AreRoutesPersisted=False (not a direct echo of the PersistRoutes setting), got "
        f"{database['AreRoutesPersisted']!r}"
    )

    # teardown note: the peer and endpoint above are discovered and deleted by
    # _teardown_route_server (registered right after CreateRouteServer), not via their own
    # on_cleanup, because they must be deleted in a strict order the shared teardown already
    # gets right.


def _wait_vpc_available(ec2, vpc_id, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
        if vpc["State"] == "available":
            return
        time.sleep(2)
    raise AssertionError("VPC never became available")


def _wait_state(ec2, describe_method, id_param, list_key, resource_id, state, timeout_s=180.0):
    describe = getattr(ec2, describe_method)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        items = describe(**{id_param: [resource_id]})[list_key]
        if items and items[0]["State"] == state:
            return items[0]
        time.sleep(5)
    raise AssertionError(f"{describe_method} never reported state {state!r} for {resource_id}")


def _wait_propagation(ec2, route_server_id, route_table_id, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ec2.get_route_server_propagations(RouteServerId=route_server_id, RouteTableId=route_table_id)
        for prop in resp.get("RouteServerPropagations", []):
            if prop["RouteTableId"] == route_table_id:
                return prop
        time.sleep(3)
    return None


def _wait_association(ec2, route_server_id, vpc_id, state, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        assocs = ec2.get_route_server_associations(RouteServerId=route_server_id)["RouteServerAssociations"]
        for assoc in assocs:
            if assoc["VpcId"] == vpc_id and assoc["State"] == state:
                return assoc
        time.sleep(3)
    raise AssertionError(f"VPC {vpc_id} never reached association state {state!r} on {route_server_id}")


def _tag_spec(resource_type, name):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


# ===== route-server teardown (self-contained) =====
# Route-server deletes are ASYNC and strictly ordered: peers block their endpoint, an
# endpoint's in-use ENI blocks DisassociateRouteServer (and DeleteSubnet/DeleteVpc), and an
# association blocks DeleteRouteServer. So the teardown retries whole passes under one shared
# budget instead of walking the chain once -- a single pass strands everything downstream of
# the first step that is still settling, and _rs_call swallows the rejection, so the leak is
# silent.
_RS_TEARDOWN_BUDGET_S = 1200.0
_RS_PEER_TERMINAL = ("deleted", "failed")
_RS_ENDPOINT_TERMINAL = ("deleted", "delete-failed", "failed")


def _rs_call(fn, **kwargs):
    """Best-effort AWS call used only during teardown, so cleanup can never mask a result."""
    try:
        return fn(**kwargs) or {}
    except Exception:  # noqa: BLE001
        return {}


def _rs_wait(remaining, *, deadline, interval_s=15.0):
    while time.monotonic() < deadline:
        if not remaining():
            return
        time.sleep(interval_s)


def _rs_peers(ec2, route_server_id):
    return [
        p
        for p in _rs_call(ec2.describe_route_server_peers).get("RouteServerPeers", [])
        if p.get("RouteServerId") == route_server_id and p.get("State") not in _RS_PEER_TERMINAL
    ]


def _rs_endpoints(ec2, route_server_id):
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
    return _rs_call(ec2.get_route_server_associations, RouteServerId=route_server_id).get(
        "RouteServerAssociations", []
    )


def _teardown_route_server(ec2, route_server_id):
    """Delete a route server and everything hanging off it, WAITING at each step.

    Registered as ONE cleanup right after CreateRouteServer, and DISCOVERY-based rather than
    id-based, so it tears down whatever peers/endpoints/propagations/associations exist no
    matter how far the check got before failing.
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
        if not live or time.monotonic() >= deadline:
            return
        time.sleep(min(15.0, max(0.0, deadline - time.monotonic())))


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation -- and swallowing that leaked the
# VPC while the check PASSED. So wait (bounded) for the resource's ENIs to go, retry
# DependencyViolation inside the same window, and raise a final failure naming the ENIs still
# attached. Every other error propagates. Teardown-only: nothing run() executes calls this, so it
# cannot change the verdict. The window is shared by all of one check's network deletes.
_NET_TEARDOWN_S = 630.0
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
        _time.sleep(10)
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
        _time.sleep(10)


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
