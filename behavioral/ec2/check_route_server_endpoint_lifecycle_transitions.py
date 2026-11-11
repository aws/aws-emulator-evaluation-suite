"""route-server-endpoint-lifecycle-transitions."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "route-server-endpoint-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRouteServerEndpoint moves pending->available before
    DeleteRouteServerEndpoint transitions it to deleting->deleted."""
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    vpc = ec2.create_vpc(CidrBlock="10.232.0.0/16")["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))

    subnet = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.232.1.0/24", AvailabilityZone=az
    )["Subnet"]
    subnet_id = subnet["SubnetId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))

    rs_id = ec2.create_route_server(AmazonSideAsn=64512)["RouteServer"]["RouteServerId"]
    # DeleteRouteServer is rejected while any association is still live, and
    # DisassociateRouteServer (registered below, so it runs FIRST under LIFO
    # cleanup) only starts that transition -- it does not wait for it. Without
    # this wait, the delete below fires on a still-"disassociating" route
    # server, is rejected, and _safe() swallows the rejection: the route
    # server (billed hourly) leaks silently.
    ctx.on_cleanup(
        lambda: _safe(
            lambda: (_wait_disassociated(ec2, rs_id, vpc_id), ec2.delete_route_server(RouteServerId=rs_id))
        )
    )
    _poll_until(
        lambda: ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"][0],
        lambda r: r["State"] == "available",
        timeout_s=180,
    )

    # A route server endpoint can only be created in a subnet whose VPC is
    # already associated with the route server.
    ec2.associate_route_server(RouteServerId=rs_id, VpcId=vpc_id)
    ctx.on_cleanup(
        lambda: _safe(lambda: ec2.disassociate_route_server(RouteServerId=rs_id, VpcId=vpc_id))
    )
    _poll_until(
        lambda: next(
            (a for a in _get_associations_safe(ec2, rs_id) if a["VpcId"] == vpc_id),
            None,
        ),
        lambda a: a is not None and a["State"] == "associated",
        timeout_s=180,
    )

    ep = ec2.create_route_server_endpoint(RouteServerId=rs_id, SubnetId=subnet_id)[
        "RouteServerEndpoint"
    ]
    ep_id = ep["RouteServerEndpointId"]
    ctx.on_cleanup(
        lambda: _safe(lambda: ec2.delete_route_server_endpoint(RouteServerEndpointId=ep_id))
    )
    assert ep["State"] in ("pending", "available")

    ep = _poll_until(
        lambda: ec2.describe_route_server_endpoints(RouteServerEndpointIds=[ep_id])[
            "RouteServerEndpoints"
        ][0],
        lambda e: e["State"] == "available",
        timeout_s=240,
    )
    assert ep["State"] == "available"
    assert ep["VpcId"] == vpc_id
    assert ep["SubnetId"] == subnet_id

    ec2.delete_route_server_endpoint(RouteServerEndpointId=ep_id)
    final = _poll_until(
        lambda: ec2.describe_route_server_endpoints(RouteServerEndpointIds=[ep_id])[
            "RouteServerEndpoints"
        ],
        lambda lst: lst == [] or lst[0]["State"] == "deleted",
        timeout_s=240,
    )
    assert final == [] or final[0]["State"] == "deleted"

    # The delete must also make the endpoint unusable, not merely absent from
    # the list: a repeat delete on the dead id is rejected, not silently
    # accepted. Measured against real AWS: a describe still returns the
    # endpoint in its terminal "deleted" state for a while (line 87-93 above),
    # and a repeat delete on that terminal-but-still-describable id is
    # rejected with IncorrectState -- not NotFound, which is what a
    # never-existed id gets instead.
    err = _error(lambda: ec2.delete_route_server_endpoint(RouteServerEndpointId=ep_id))
    assert err["Code"] == "IncorrectState", f"expected IncorrectState, got {err!r}"
    assert err.get("Message") == f"Route Server Endpoint {ep_id} is in an invalid state.", (
        f"unexpected message: {err.get('Message')!r}"
    )


# ===== helpers =====
def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidNetworkInterfaceID.NotFound",
            "InvalidRouteServerEndpointId.NotFound",
            "InvalidRouteServerId.NotAssociated",
            "InvalidRouteServerId.NotFound",
            "InvalidVpcID.NotFound",
        ):
            raise


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError("expected a ClientError, call succeeded")


def _wait_disassociated(ec2, rs_id, vpc_id, timeout_s=180.0, interval_s=5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if not any(a["VpcId"] == vpc_id for a in _get_associations_safe(ec2, rs_id)):
            return
        time.sleep(interval_s)


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


# Network teardown: an async delete's AWS-managed ENIs hold the subnet / security group / VPC in
# DependencyViolation, so wait for them to go and retry DependencyViolation to one deadline shared by
# all of a check's network deletes (within the suite cleanup budget), then raise naming the ENIs left.
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
