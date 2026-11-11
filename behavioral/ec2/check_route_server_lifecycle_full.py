"""route-server-lifecycle-full."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "route-server-lifecycle-full"
GROUP = "state-machine"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A route server peer created on an endpoint of an associated route server reports its endpoint id,
    peer address and a documented state; after the full teardown sequence the route server is deleted
    and AssociateRouteServer on it fails with IncorrectState and its exact message."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-rs-")

    vpc_id = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"][0][
        "VpcId"
    ]

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    subnet_id, subnet_cidr = _create_subnet_with_retry(ec2, vpc_id, az, name)
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))


    rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=_tag_spec("route-table", name)
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=rt_id))


    # 1. CreateRouteServer -> available
    rs_id = ec2.create_route_server(
        AmazonSideAsn=64512, TagSpecifications=_tag_spec("route-server", name)
    )["RouteServer"]["RouteServerId"]
    ctx.on_cleanup(lambda: _delete_quiet(lambda: ec2.delete_route_server(RouteServerId=rs_id)))

    def _rs_state():
        rs = ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"][0]
        return rs["State"]

    _poll_until(_rs_state, lambda s: s == "available", timeout_s=120, interval_s=3)

    # 2. AssociateRouteServer -> GetRouteServerAssociations shows 'associated'.
    # CreateRouteServerEndpoint requires the route
    # server to already be associated with the VPC that owns the endpoint's
    # subnet, so association must happen before endpoint creation.
    ec2.associate_route_server(RouteServerId=rs_id, VpcId=vpc_id)

    def _assoc_state():
        assocs = ec2.get_route_server_associations(RouteServerId=rs_id)["RouteServerAssociations"]
        for a in assocs:
            if a["VpcId"] == vpc_id:
                return a["State"]
        return None

    _poll_until(_assoc_state, lambda s: s == "associated", timeout_s=120, interval_s=3)

    # 3. CreateRouteServerEndpoint -> available
    ep_id = ec2.create_route_server_endpoint(
        RouteServerId=rs_id,
        SubnetId=subnet_id,
        TagSpecifications=_tag_spec("route-server-endpoint", name),
    )["RouteServerEndpoint"]["RouteServerEndpointId"]
    ctx.on_cleanup(lambda: _delete_quiet(lambda: ec2.delete_route_server_endpoint(RouteServerEndpointId=ep_id)))

    def _ep_state():
        eps = ec2.describe_route_server_endpoints(RouteServerEndpointIds=[ep_id])
        return eps["RouteServerEndpoints"][0]["State"]

    _poll_until(_ep_state, lambda s: s == "available", timeout_s=180, interval_s=5)

    # 4. CreateRouteServerPeer -- visible via DescribeRouteServerPeers immediately
    import ipaddress

    peer_addr = str(list(ipaddress.ip_network(subnet_cidr).hosts())[10])

    peer_id = ec2.create_route_server_peer(
        RouteServerEndpointId=ep_id,
        PeerAddress=peer_addr,
        BgpOptions={"PeerAsn": 65001},
        TagSpecifications=_tag_spec("route-server-peer", name),
    )["RouteServerPeer"]["RouteServerPeerId"]
    ctx.on_cleanup(lambda: _delete_quiet(lambda: ec2.delete_route_server_peer(RouteServerPeerId=peer_id)))

    peers = ec2.describe_route_server_peers(RouteServerPeerIds=[peer_id])["RouteServerPeers"]
    assert len(peers) == 1, f"expected exactly 1 peer for {peer_id}, got {len(peers)}"
    assert peers[0]["RouteServerEndpointId"] == ep_id, (
        f"peer's endpoint id mismatch: expected {ep_id}, got {peers[0]['RouteServerEndpointId']!r}"
    )
    assert peers[0]["PeerAddress"] == peer_addr, (
        f"peer address mismatch: expected {peer_addr}, got {peers[0]['PeerAddress']!r}"
    )
    assert peers[0]["State"] in ("pending", "available", "failing", "failed"), (
        f"unexpected peer state right after creation: {peers[0]['State']!r}"
    )

    # The peer session never actually establishes (there is no real BGP
    # speaker at that address), so it settles from the transient 'pending'
    # into a stable terminal-ish state ('available' once the endpoint
    # accepts a session config, or 'failing'/'failed' once retries are
    # exhausted). DeleteRouteServerPeer is rejected with IncorrectState
    # while still 'pending', so wait for that transient window to close.
    def _peer_state():
        peers = ec2.describe_route_server_peers(RouteServerPeerIds=[peer_id])["RouteServerPeers"]

        return peers[0]["State"] if peers else None

    _poll_until(
        _peer_state, lambda s: s in ("available", "failing", "failed"), timeout_s=180, interval_s=5
    )

    # 5. EnableRouteServerPropagation -> GetRouteServerPropagations shows 'available'
    ec2.enable_route_server_propagation(RouteServerId=rs_id, RouteTableId=rt_id)

    def _prop_state():
        props = ec2.get_route_server_propagations(RouteServerId=rs_id, RouteTableId=rt_id)[
            "RouteServerPropagations"
        ]
        for p in props:
            if p["RouteTableId"] == rt_id:
                return p["State"]
        return None

    _poll_until(_prop_state, lambda s: s == "available", timeout_s=120, interval_s=3)

    # 6. Disable propagation and delete the peer + endpoint before
    # disassociating. DisassociateRouteServer is rejected while
    # the route server still has a non-deleted propagation OR a non-deleted
    # endpoint in that VPC, so the teardown order must be:
    # disable-propagation -> delete-peer -> delete-endpoint -> disassociate -> delete-route-server.
    ec2.disable_route_server_propagation(RouteServerId=rs_id, RouteTableId=rt_id)

    def _prop_gone():
        try:
            props = ec2.get_route_server_propagations(RouteServerId=rs_id, RouteTableId=rt_id)[
                "RouteServerPropagations"
            ]
        except Exception as exc:
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError) and exc.response["Error"]["Code"] == "InvalidRouteServerId.NotPropagated":
                return True
            raise
        return not any(p["RouteTableId"] == rt_id and p["State"] not in ("deleted",) for p in props)

    _poll_until(_prop_gone, lambda ok: ok, timeout_s=120, interval_s=3)

    # 7. DeleteRouteServerPeer -> peer disappears
    ec2.delete_route_server_peer(RouteServerPeerId=peer_id)

    def _peer_gone():
        peers = ec2.describe_route_server_peers(RouteServerPeerIds=[peer_id])["RouteServerPeers"]
        return len(peers) == 0 or peers[0]["State"] == "deleted"

    _poll_until(lambda: _peer_gone(), lambda ok: ok, timeout_s=120, interval_s=3)

    # 8. DeleteRouteServerEndpoint -> endpoint disappears
    ec2.delete_route_server_endpoint(RouteServerEndpointId=ep_id)

    def _ep_gone():
        eps = ec2.describe_route_server_endpoints(RouteServerEndpointIds=[ep_id])[
            "RouteServerEndpoints"
        ]
        return len(eps) == 0 or eps[0]["State"] == "deleted"

    _poll_until(lambda: _ep_gone(), lambda ok: ok, timeout_s=180, interval_s=5)

    # 9. DisassociateRouteServer -> association disappears from GetRouteServerAssociations
    ec2.disassociate_route_server(RouteServerId=rs_id, VpcId=vpc_id)

    def _assoc_gone():
        try:
            assocs = ec2.get_route_server_associations(RouteServerId=rs_id)["RouteServerAssociations"]
        except Exception as exc:
            # Once the last association is removed, real AWS raises
            # InvalidRouteServerId.NotAssociated instead of returning an
            # empty list.
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError) and exc.response["Error"]["Code"] == "InvalidRouteServerId.NotAssociated":
                return True
            raise
        return not any(a["VpcId"] == vpc_id for a in assocs)

    _poll_until(lambda: _assoc_gone(), lambda ok: ok, timeout_s=120, interval_s=3)

    # 10. DeleteRouteServer -> terminal 404
    ec2.delete_route_server(RouteServerId=rs_id)

    def _rs_gone():
        try:
            rss = ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"]
        except ClientError as exc:
            return exc.response["Error"]["Code"]
        return "deleted" if (rss and rss[0]["State"] == "deleted") else None

    def _terminal(v):
        return v == "InvalidRouteServerID.NotFound" or v == "deleted"

    _poll_until(_rs_gone, _terminal, timeout_s=180, interval_s=5)

    # The deleted route server id must also be unusable for a mutation, not
    # merely absent from a read. A deleted route
    # server still describes in state 'deleted' rather than 404ing, so a
    # mutation against it is rejected with IncorrectState, not NotFound.
    err = _error(lambda: ec2.associate_route_server(RouteServerId=rs_id, VpcId=vpc_id))
    assert err["Code"] == "IncorrectState", f"expected IncorrectState, got {err!r}"
    assert err.get("Message") == f"Route Server {rs_id} is in an invalid state.", (
        f"unexpected message: {err.get('Message')!r}"
    )



def _tag_spec(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _pick_free_subnet_cidr(ec2, vpc_id: str, new_prefix: int = 24) -> str:
    """Finds an unused /new_prefix CIDR inside vpc_id's CIDR block(s) that
    does not overlap any existing subnet -- avoids needing to create a brand
    new VPC (a scarce, tightly-quota-limited resource) just to get a subnet."""
    import ipaddress

    vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    vpc_cidrs = [a["CidrBlock"] for a in vpc.get("CidrBlockAssociationSet", []) if a.get("CidrBlock")]
    if not vpc_cidrs:
        vpc_cidrs = [vpc["CidrBlock"]]

    existing = [
        ipaddress.ip_network(s["CidrBlock"])
        for s in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    ]

    for vpc_cidr in vpc_cidrs:
        vpc_net = ipaddress.ip_network(vpc_cidr)
        if vpc_net.prefixlen > new_prefix:
            continue
        for candidate in vpc_net.subnets(new_prefix=new_prefix):
            if not any(candidate.overlaps(existing_net) for existing_net in existing):
                return str(candidate)
    raise AssertionError(f"no free /{new_prefix} CIDR found in VPC {vpc_id}")


def _create_subnet_with_retry(ec2, vpc_id: str, az: str, name: str, attempts: int = 6):
    """Picking a free CIDR and creating the subnet is not atomic, so a
    concurrent check on the same shared default VPC can race us for the
    same candidate CIDR (InvalidSubnet.Conflict). Recompute and retry.
    Returns (subnet_id, cidr_used)."""
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(attempts):
        cidr = _pick_free_subnet_cidr(ec2, vpc_id)
        try:
            subnet_id = ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock=cidr,
                AvailabilityZone=az,
                TagSpecifications=_tag_spec("subnet", name),
            )["Subnet"]["SubnetId"]
            return subnet_id, cidr
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidSubnet.Conflict":
                raise
            last_exc = exc
    raise last_exc




def _delete_quiet(fn: Callable[[], Any]) -> None:
    """Cleanup: delete, tolerating a resource the check already deleted (a deleted
    route server object rejects a repeat delete with IncorrectState)."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code != "IncorrectState" and not code.endswith(".NotFound"):
            raise


def _error(fn: Callable[[], Any]):
    """Call fn(); return its ClientError Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
