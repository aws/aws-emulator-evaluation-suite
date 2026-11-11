"""create-route-server-peer-malformed-asn-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-route-server-peer-malformed-asn-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRouteServerPeer rejects a negative BGP peer ASN with a specific validation error, while a
    valid private ASN creates the peer."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-rspeer-asn-")
    tag_spec = lambda resource_type: [
        {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}
    ]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.213.0.0/16", TagSpecifications=tag_spec("vpc")
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.213.1.0/24", TagSpecifications=tag_spec("subnet")
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    route_server_id = ec2.create_route_server(
        AmazonSideAsn=4200000000, TagSpecifications=tag_spec("route-server")
    )["RouteServer"]["RouteServerId"]
    ctx.on_cleanup(lambda: _retry_in_use(ec2, lambda: ec2.delete_route_server(RouteServerId=route_server_id)))

    # CreateRouteServerEndpoint requires the route server to already be associated with the
    # endpoint's VPC -- an unassociated route server rejects it with
    # InvalidRouteServerId.NotAssociated.
    ec2.associate_route_server(RouteServerId=route_server_id, VpcId=vpc_id)
    ctx.on_cleanup(
        lambda: _disassociate_and_wait(ec2, route_server_id, vpc_id)
    )
    _poll_until(
        lambda: _association_state(ec2, route_server_id, vpc_id),
        lambda state: state == "associated",
        timeout_s=120,
        interval_s=5,
    )

    endpoint_id = ec2.create_route_server_endpoint(
        RouteServerId=route_server_id,
        SubnetId=subnet_id,
        TagSpecifications=tag_spec("route-server-endpoint"),
    )["RouteServerEndpoint"]["RouteServerEndpointId"]
    ctx.on_cleanup(lambda: _delete_endpoint_and_wait(ec2, endpoint_id))

    _poll_until(
        lambda: ec2.describe_route_server_endpoints(RouteServerEndpointIds=[endpoint_id])[
            "RouteServerEndpoints"
        ][0]["State"],
        lambda state: state == "available",
        timeout_s=300,
        interval_s=5,
    )

    # Negative: a negative ASN is malformed by construction -- no BGP ASN is negative.
    code, message = _error(
        lambda: ec2.create_route_server_peer(
            RouteServerEndpointId=endpoint_id,
            PeerAddress="10.213.1.100",
            BgpOptions={"PeerAsn": -1},
        )
    )
    assert code == "InvalidParameterValue", (
        f"expected InvalidParameterValue for PeerAsn=-1, got {code!r}"
    )
    assert message == "Value (PeerAsn) for -1 is invalid.", message

    # Effect absence: no peer was created on this endpoint. DescribeRouteServerPeers has no
    # route-server-endpoint-id filter ("Filter type route-server-endpoint-id is invalid for
    # this operation" on real AWS) so this filters client-side instead.
    peers = [
        p
        for p in ec2.describe_route_server_peers()["RouteServerPeers"]
        if p["RouteServerEndpointId"] == endpoint_id
    ]
    assert peers == [], (
        f"a peer was created on {endpoint_id} despite the malformed PeerAsn=-1: {peers!r}"
    )

    # Positive control: a valid private ASN succeeds in creating the peer object.
    peer_id = ec2.create_route_server_peer(
        RouteServerEndpointId=endpoint_id,
        PeerAddress="10.213.1.100",
        BgpOptions={"PeerAsn": 65001},
        TagSpecifications=tag_spec("route-server-peer"),
    )["RouteServerPeer"]["RouteServerPeerId"]
    ctx.on_cleanup(lambda: _delete_peer_and_wait(ec2, peer_id))

    peers_after = [
        p
        for p in ec2.describe_route_server_peers()["RouteServerPeers"]
        if p["RouteServerEndpointId"] == endpoint_id
    ]
    assert any(p["RouteServerPeerId"] == peer_id for p in peers_after), (
        f"peer {peer_id} created with a valid ASN did not appear in "
        f"describe_route_server_peers: {peers_after!r}"
    )


# ===== helpers =====
def _association_state(ec2, route_server_id, vpc_id):
    from botocore.exceptions import ClientError

    try:
        assocs = ec2.get_route_server_associations(RouteServerId=route_server_id)[
            "RouteServerAssociations"
        ]
    except ClientError as err:
        # Once disassociation has fully cleared, GetRouteServerAssociations stops
        # returning an empty list and instead raises this -- observed on real AWS.
        if err.response["Error"]["Code"] == "InvalidRouteServerId.NotAssociated":
            return None
        raise
    for assoc in assocs:
        if assoc["VpcId"] == vpc_id:
            return assoc["State"]
    return None


def _delete_peer_and_wait(ec2, peer_id):
    """Delete the peer and wait until it is gone, so the endpoint delete after it is not refused."""
    from botocore.exceptions import ClientError

    try:
        _retry_in_use(ec2, lambda: ec2.delete_route_server_peer(RouteServerPeerId=peer_id))
        while _teardown_left(ec2) > 0:
            peers = ec2.describe_route_server_peers(RouteServerPeerIds=[peer_id])["RouteServerPeers"]
            if not peers or peers[0]["State"] == "deleted":
                return
            time.sleep(2)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidRouteServerPeerId.NotFound":
            raise
        return
    raise AssertionError(f"route server peer {peer_id} still not deleted at the cleanup deadline")


def _delete_endpoint_and_wait(ec2, endpoint_id):
    from botocore.exceptions import ClientError

    try:
        _retry_in_use(ec2, lambda: ec2.delete_route_server_endpoint(RouteServerEndpointId=endpoint_id))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidRouteServerEndpointId.NotFound":
            raise

    def _endpoint_state():
        eps = ec2.describe_route_server_endpoints(RouteServerEndpointIds=[endpoint_id])[
            "RouteServerEndpoints"
        ]
        return eps[0]["State"] if eps else None

    try:
        _poll_until(
            _endpoint_state, lambda s: s in (None, "deleted"), timeout_s=max(_teardown_left(ec2), 1.0), interval_s=5.0
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidRouteServerEndpointId.NotFound":
            raise


def _disassociate_and_wait(ec2, route_server_id, vpc_id, *, timeout_s=120.0):
    from botocore.exceptions import ClientError

    try:
        _retry_in_use(ec2, lambda: ec2.disassociate_route_server(RouteServerId=route_server_id, VpcId=vpc_id))
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidRouteServerId.NotAssociated",
            "InvalidVpcID.NotFound",
        ):
            raise
    _poll_until(
        lambda: _association_state(ec2, route_server_id, vpc_id),
        lambda state: state is None,
        timeout_s=timeout_s,
        interval_s=5.0,
    )


# budget.cleanup_timeout for behavioral/ec2: one deadline shared by the check's route-server teardowns.
_TEARDOWN_RETRY_S = 900.0
_TEARDOWN_DEADLINES: dict = {}


def _teardown_left(ec2) -> float:
    held = _TEARDOWN_DEADLINES.get(id(ec2))
    if held is None or held[0] is not ec2:
        held = _TEARDOWN_DEADLINES[id(ec2)] = (ec2, time.monotonic() + _TEARDOWN_RETRY_S)
    return held[1] - time.monotonic()


def _retry_in_use(ec2, fn):
    """Retry fn on IncorrectState (a dependent is still deleting) and throttling every 2 s to the
    shared cleanup deadline; raise everything else."""
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("IncorrectState", "RequestLimitExceeded") or _teardown_left(ec2) <= 0:
                raise
        time.sleep(2)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


# EC2 network teardown: an asynchronously deleted dependent leaves its ENIs in the subnet / security
# group, so each delete retries DependencyViolation while they drain, inside one window shared by the
# check's network deletes and the suite's cleanup budget, then raises naming the ENIs still attached.
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
