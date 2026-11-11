"""delete-route-server-with-active-peer-blocked."""
from __future__ import annotations

import ipaddress
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-route-server-with-active-peer-blocked"
GROUP = "overly-permissive"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRouteServer with a live BGP peer is refused with IncorrectState "Route Server has non-deleted
    association with VPC: <vpc>.", as it still is with only the association left; after the peer, endpoint
    and association are removed it deletes.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-rsapeer-")

    # The run's shared network (ctx.network()) is used, as VPCs are tightly quota-limited.
    vpc_id = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"][0][
        "VpcId"
    ]
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    subnet_id, subnet_cidr = _create_subnet_with_retry(ec2, vpc_id, az, name)
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    rs_id = ec2.create_route_server(
        AmazonSideAsn=64512, TagSpecifications=_tag_spec("route-server", name)
    )["RouteServer"]["RouteServerId"]
    ctx.on_cleanup(lambda: _ignore_error(lambda: ec2.delete_route_server(RouteServerId=rs_id)))

    def _rs_state():
        return ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"][0]["State"]

    _poll_until(_rs_state, lambda s: s == "available", timeout_s=120, interval_s=3)

    # CreateRouteServerEndpoint requires the route
    # server to already be associated with the VPC that owns the endpoint's
    # subnet.
    ec2.associate_route_server(RouteServerId=rs_id, VpcId=vpc_id)

    def _assoc_state():
        assocs = ec2.get_route_server_associations(RouteServerId=rs_id)["RouteServerAssociations"]
        for a in assocs:
            if a["VpcId"] == vpc_id:
                return a["State"]
        return None

    _poll_until(_assoc_state, lambda s: s == "associated", timeout_s=120, interval_s=3)

    ep_id = ec2.create_route_server_endpoint(
        RouteServerId=rs_id,
        SubnetId=subnet_id,
        TagSpecifications=_tag_spec("route-server-endpoint", name),
    )["RouteServerEndpoint"]["RouteServerEndpointId"]
    ctx.on_cleanup(
        lambda: _ignore_error(lambda: ec2.delete_route_server_endpoint(RouteServerEndpointId=ep_id))
    )

    def _ep_state():
        eps = ec2.describe_route_server_endpoints(RouteServerEndpointIds=[ep_id])["RouteServerEndpoints"]
        return eps[0]["State"] if eps else None

    _poll_until(_ep_state, lambda s: s == "available", timeout_s=180, interval_s=5)

    peer_addr = str(list(ipaddress.ip_network(subnet_cidr).hosts())[10])
    peer_id = ec2.create_route_server_peer(
        RouteServerEndpointId=ep_id,
        PeerAddress=peer_addr,
        BgpOptions={"PeerAsn": 65001},
        TagSpecifications=_tag_spec("route-server-peer", name),
    )["RouteServerPeer"]["RouteServerPeerId"]
    ctx.on_cleanup(
        lambda: _ignore_error(lambda: ec2.delete_route_server_peer(RouteServerPeerId=peer_id))
    )

    def _peer_state():
        peers = ec2.describe_route_server_peers(RouteServerPeerIds=[peer_id])["RouteServerPeers"]
        return peers[0]["State"] if peers else None

    # The peer session never actually establishes (no real BGP speaker at
    # that address), so wait for it to leave the transient 'pending' window.
    _poll_until(_peer_state, lambda s: s in ("available", "failing", "failed"), timeout_s=180, interval_s=5)

    # ---- Negative: DeleteRouteServer is rejected while the peer is live ----
    # AWS answers IncorrectState, not DependencyViolation, naming the VPC association, the first
    # blocker it reports while the peer and endpoint are still live.
    code, msg = _client_error(lambda: ec2.delete_route_server(RouteServerId=rs_id))
    assert code == "IncorrectState", f"expected IncorrectState, got {code!r}"
    expected_msg = f"Route Server has non-deleted association with VPC: {vpc_id}."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Effect absence: the route server is unaffected.
    still_there = ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"]
    assert len(still_there) == 1, f"expected exactly 1 route server, got {len(still_there)}"
    assert still_there[0]["State"] == "available", (
        f"expected the route server to remain 'available' after the rejected delete, "
        f"got {still_there[0]['State']!r}"
    )

    # ---- Positive control: tear down the peer + endpoint, then delete succeeds ----
    ec2.delete_route_server_peer(RouteServerPeerId=peer_id)

    def _peer_gone():
        peers = ec2.describe_route_server_peers(RouteServerPeerIds=[peer_id])["RouteServerPeers"]
        return not peers or peers[0]["State"] == "deleted"

    _poll_until(_peer_gone, lambda ok: ok, timeout_s=120, interval_s=3)

    ec2.delete_route_server_endpoint(RouteServerEndpointId=ep_id)

    def _ep_gone():
        eps = ec2.describe_route_server_endpoints(RouteServerEndpointIds=[ep_id])["RouteServerEndpoints"]
        return not eps or eps[0]["State"] == "deleted"

    _poll_until(_ep_gone, lambda ok: ok, timeout_s=180, interval_s=5)

    # ---- Isolation: peer and endpoint are gone, the VPC association is still live. The same
    # refusal here shows the association, which CreateRouteServerEndpoint required, is what blocks.
    mid_code, mid_msg = _client_error(lambda: ec2.delete_route_server(RouteServerId=rs_id))
    assert mid_code == "IncorrectState", (
        f"expected the still-live VPC association alone to reproduce IncorrectState "
        f"now that the peer and endpoint are gone, got {mid_code!r}"
    )
    expected_msg = f"Route Server has non-deleted association with VPC: {vpc_id}."
    assert mid_msg == expected_msg, f"expected message {expected_msg!r}, got {mid_msg!r}"
    still_associated = ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"]
    assert len(still_associated) == 1, f"expected exactly 1 route server, got {len(still_associated)}"
    assert still_associated[0]["State"] == "available", (
        f"expected the route server to remain 'available' after the association-only "
        f"rejection, got {still_associated[0]['State']!r}"
    )

    ec2.disassociate_route_server(RouteServerId=rs_id, VpcId=vpc_id)

    def _assoc_gone():
        try:
            assocs = ec2.get_route_server_associations(RouteServerId=rs_id)["RouteServerAssociations"]
        except Exception as exc:
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError) and exc.response["Error"]["Code"] == "InvalidRouteServerId.NotAssociated":
                return True
            raise
        return not any(a["VpcId"] == vpc_id for a in assocs)

    _poll_until(_assoc_gone, lambda ok: ok, timeout_s=120, interval_s=3)

    ec2.delete_route_server(RouteServerId=rs_id)

    def _rs_terminal() -> bool:
        from botocore.exceptions import ClientError

        try:
            rss = ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"]
        except ClientError:
            return True
        return bool(rss) and rss[0]["State"] == "deleted"

    _poll_until(_rs_terminal, lambda ok: ok, timeout_s=180, interval_s=5)


def _tag_spec(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _pick_free_subnet_cidr(ec2, vpc_id: str, new_prefix: int = 24) -> str:
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


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _ignore_error(fn: Callable[[], Any]) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidRouteServerEndpointId.NotFound",
            "InvalidRouteServerId.NotFound",
            "InvalidRouteServerPeerId.NotFound",
        ):
            raise


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
