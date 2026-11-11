"""op-contract-deleteTransitGatewayConnectPeer."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteTransitGatewayConnectPeer"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTransitGatewayConnectPeer on an available Connect peer answers deleting or deleted and the
    peer reaches deleted; an unknown peer ID fails with a NotFound code."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgwcp-")

    tgw_id = _create_tgw(ctx, ec2, name)
    vpc_id, subnet_id = _create_vpc_and_subnet(ctx, ec2, name)
    transport_id = _create_vpc_attachment(ctx, ec2, tgw_id, vpc_id, subnet_id, name)
    _wait_attachment_state(ec2, transport_id, "available", timeout_s=240.0)
    connect_id = _create_connect(ctx, ec2, transport_id, name)
    _wait_attachment_state(ec2, connect_id, "available", timeout_s=240.0)

    peer_created = ec2.create_transit_gateway_connect_peer(
        TransitGatewayAttachmentId=connect_id,
        PeerAddress="10.212.0.200",
        InsideCidrBlocks=["169.254.20.0/29"],
        TagSpecifications=[{"ResourceType": "transit-gateway-connect-peer", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    peer_id = peer_created["TransitGatewayConnectPeer"]["TransitGatewayConnectPeerId"]
    ctx.on_cleanup(
        lambda: _best_effort(lambda: ec2.delete_transit_gateway_connect_peer(TransitGatewayConnectPeerId=peer_id))
    )

    # Connect peer provisioning (BGP session bring-up over the GRE tunnel) takes longer than a
    # plain attachment and can exceed 180 s.
    state = _wait_connect_peer_state(ec2, peer_id, "available", timeout_s=420.0)
    assert state == "available", f"connect peer never became available (last={state})"

    delete_resp = ec2.delete_transit_gateway_connect_peer(TransitGatewayConnectPeerId=peer_id)
    delete_state = delete_resp["TransitGatewayConnectPeer"]["State"]
    assert delete_state in ("deleting", "deleted"), f"unexpected state after delete: {delete_state}"

    final_state = _wait_connect_peer_state(ec2, peer_id, "deleted", timeout_s=300.0, treat_notfound_as="deleted")
    assert final_state == "deleted", f"connect peer never reached deleted (last={final_state})"

    code = _error_code(
        lambda: ec2.delete_transit_gateway_connect_peer(TransitGatewayConnectPeerId="tgw-connect-peer-0123456789abcdef0")
    )
    assert code is not None and code.endswith("NotFound"), f"unexpected error code: {code}"


# ===== helpers =====

def _poll(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_code(fn):
    """Call fn(); return its error code. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _wait_attachment_state(ec2, attach_id, target, timeout_s=180.0, treat_notfound_as=None):
    def probe():
        try:
            resp = ec2.describe_transit_gateway_attachments(TransitGatewayAttachmentIds=[attach_id])
            atts = resp["TransitGatewayAttachments"]
            if not atts:
                return treat_notfound_as
            return atts[0]["State"]
        except ClientError as exc:
            if treat_notfound_as and "NotFound" in exc.response["Error"]["Code"]:
                return treat_notfound_as
            raise

    return _poll(probe, lambda s: s == target, timeout_s=timeout_s)


def _wait_connect_peer_state(ec2, peer_id, target, timeout_s=180.0, treat_notfound_as=None):
    def probe():
        try:
            resp = ec2.describe_transit_gateway_connect_peers(TransitGatewayConnectPeerIds=[peer_id])
            peers = resp["TransitGatewayConnectPeers"]
            if not peers:
                return treat_notfound_as
            return peers[0]["State"]
        except ClientError as exc:
            if treat_notfound_as and "NotFound" in exc.response["Error"]["Code"]:
                return treat_notfound_as
            raise

    return _poll(probe, lambda s: s == target, timeout_s=timeout_s)


def _retry_on_tgw_limit(fn, timeout_s=600.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TransitGatewayLimitExceeded" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_tgw(ctx, ec2, name):
    # A Connect peer needs a CIDR block to auto-assign its TransitGatewayAddress from;
    # without one, CreateTransitGatewayConnectPeer rejects with MissingParameter.
    created = _retry_on_tgw_limit(
        lambda: ec2.create_transit_gateway(
            Description=name,
            Options={"TransitGatewayCidrBlocks": ["10.221.0.0/24"]},
            TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
        )
    )
    tgw_id = created["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id)))
    _poll(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=180.0,
    )
    return tgw_id


def _create_vpc_and_subnet(ctx, ec2, name):
    vpc = ec2.create_vpc(
        CidrBlock="10.213.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    vpc_id = vpc["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), busy_s=0))
    _poll(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
        lambda s: s == "available",
        timeout_s=60.0,
    )
    subnet = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.213.0.0/26",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    subnet_id = subnet["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id), busy_s=0))
    return vpc_id, subnet_id


def _create_vpc_attachment(ctx, ec2, tgw_id, vpc_id, subnet_id, name):
    created = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw_id,
        VpcId=vpc_id,
        SubnetIds=[subnet_id],
        TagSpecifications=[{"ResourceType": "transit-gateway-attachment", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    attach_id = created["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
    ctx.on_cleanup(
        lambda: _best_effort(lambda: ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attach_id))
    )
    return attach_id


def _create_connect(ctx, ec2, transport_id, name):
    created = ec2.create_transit_gateway_connect(
        TransportTransitGatewayAttachmentId=transport_id,
        Options={"Protocol": "gre"},
        TagSpecifications=[{"ResourceType": "transit-gateway-attachment", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    connect_id = created["TransitGatewayConnect"]["TransitGatewayAttachmentId"]
    ctx.on_cleanup(
        lambda: _best_effort(lambda: ec2.delete_transit_gateway_connect(TransitGatewayAttachmentId=connect_id))
    )
    return connect_id


# A parent delete is refused while a child it depends on is still deleting. Per call, and
# together with the network teardown, the retries fit the suite cleanup budget.
_BUSY = ("IncorrectState", "DependencyViolation")
_BUSY_RETRY_S = 90.0


def _best_effort(fn, busy_s=_BUSY_RETRY_S):
    """Run one teardown call: already gone returns; refused as busy is retried every 2 s for up
    to busy_s; anything else raises."""
    deadline = time.monotonic() + busy_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in (
                "InvalidNetworkInterfaceID.NotFound",
                "InvalidTransitGatewayAttachmentID.NotFound",
                "InvalidTransitGatewayConnectPeerID.NotFound",
                "InvalidTransitGatewayID.NotFound",
            ):
                return
            if code not in _BUSY or time.monotonic() >= deadline:
                raise
        time.sleep(2)


# AWS-managed ENIs leave a VPC asynchronously after their owner's delete returns, so DeleteSubnet,
# DeleteSecurityGroup and DeleteVpc can fail with DependencyViolation: wait for the ENIs to go,
# retry inside the same window, and raise naming any ENI still attached.
_NET_TEARDOWN_S = 240.0
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
