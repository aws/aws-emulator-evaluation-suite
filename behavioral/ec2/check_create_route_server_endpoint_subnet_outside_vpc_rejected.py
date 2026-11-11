"""create-route-server-endpoint-subnet-outside-vpc-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-route-server-endpoint-subnet-outside-vpc-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRouteServerEndpoint rejects a SubnetId from a VPC other than the route server's
    associated one and creates no endpoint; the same call with a subnet in that VPC succeeds."""
    ec2 = ctx.client("ec2")

    vpc_a = ec2.create_vpc(
        CidrBlock="10.75.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-rsep-vpc-a-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_a)))
    subnet_a = ec2.create_subnet(VpcId=vpc_a, CidrBlock="10.75.1.0/24")["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_a)))

    vpc_b = ec2.create_vpc(
        CidrBlock="10.76.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-rsep-vpc-b-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_b)))
    subnet_b = ec2.create_subnet(VpcId=vpc_b, CidrBlock="10.76.1.0/24")["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_b)))

    rs_id = ec2.create_route_server(AmazonSideAsn=64514)["RouteServer"]["RouteServerId"]
    ctx.on_cleanup(lambda: _safe(lambda: _retry_in_use(ec2, lambda: ec2.delete_route_server(RouteServerId=rs_id))))

    ec2.associate_route_server(RouteServerId=rs_id, VpcId=vpc_a)
    ctx.on_cleanup(lambda: _safe(lambda: _disassociate_and_wait(ec2, rs_id, vpc_a)))
    _poll_until(
        lambda: _assoc_state(ec2, rs_id, vpc_a),
        lambda s: s == "associated",
        timeout_s=120.0,
        reason=f"route server {rs_id} association with {vpc_a} to reach 'associated'",
    )

    # --- Negative: subnet_b belongs to vpc_b, not the route server's vpc_a ---
    code = _error_code(
        lambda: ec2.create_route_server_endpoint(RouteServerId=rs_id, SubnetId=subnet_b)
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"

    # Effect absent: no endpoint was created for this route server. DescribeRouteServerEndpoints
    # has no route-server-id filter (real AWS rejects one with InvalidParameterValue), so list and
    # filter client-side.
    all_endpoints = ec2.describe_route_server_endpoints().get("RouteServerEndpoints", [])
    endpoints = [e for e in all_endpoints if e.get("RouteServerId") == rs_id]
    assert endpoints == [], f"an endpoint was created despite the cross-VPC subnet being invalid: {endpoints}"

    # --- Positive control: subnet_a belongs to the route server's own vpc_a ---
    endpoint = ec2.create_route_server_endpoint(RouteServerId=rs_id, SubnetId=subnet_a)[
        "RouteServerEndpoint"
    ]
    endpoint_id = endpoint["RouteServerEndpointId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_endpoint_and_wait(ec2, endpoint_id)))

    final = _poll_until(
        lambda: ec2.describe_route_server_endpoints(RouteServerEndpointIds=[endpoint_id])[
            "RouteServerEndpoints"
        ][0],
        lambda e: e["State"] in ("available", "failed"),
        timeout_s=180.0,
        interval_s=5.0,
        reason=f"route server endpoint {endpoint_id} to reach a terminal state",
    )
    assert final["State"] == "available", f"endpoint never became available: {final}"
    assert final["SubnetId"] == subnet_a


# ===== helpers =====
def _delete_endpoint_and_wait(ec2, endpoint_id: str) -> None:
    """Delete the endpoint and wait until it is gone, so the disassociate after it is not refused."""
    _retry_in_use(ec2, lambda: ec2.delete_route_server_endpoint(RouteServerEndpointId=endpoint_id))

    def _state():
        eps = ec2.describe_route_server_endpoints(RouteServerEndpointIds=[endpoint_id]).get(
            "RouteServerEndpoints", []
        )
        return eps[0]["State"] if eps else None

    _poll_until(_state, lambda s: s in (None, "deleted"), timeout_s=max(_teardown_left(ec2), 1.0), interval_s=5.0)


def _disassociate_and_wait(ec2, route_server_id: str, vpc_id: str, *, timeout_s: float = 120.0) -> None:
    """Disassociate and wait for the async teardown to fully clear -- a bare
    fire-and-forget disassociate leaves the association in 'disassociating'
    for a few seconds, during which a subsequent DeleteRouteServer/DeleteVpc
    in the same cleanup chain fails with DependencyViolation and (being
    best-effort) silently orphans the VPC."""
    try:
        _retry_in_use(ec2, lambda: ec2.disassociate_route_server(RouteServerId=route_server_id, VpcId=vpc_id))
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidRouteServerId.NotAssociated",
            "InvalidVpcID.NotFound",
        ):
            raise
    _poll_until(
        lambda: _assoc_state(ec2, route_server_id, vpc_id),
        lambda s: s is None,
        timeout_s=timeout_s,
        reason=f"route server {route_server_id} association with {vpc_id} to fully clear",
    )


def _assoc_state(ec2, route_server_id: str, vpc_id: str):
    assocs = ec2.get_route_server_associations(RouteServerId=route_server_id).get(
        "RouteServerAssociations", []
    )
    for a in assocs:
        if a["VpcId"] == vpc_id:
            return a["State"]
    return None


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


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 3.0, reason: str = ""):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise TimeoutError(
        f"timed out after {timeout_s}s waiting for {reason or 'predicate'}: last value {value!r}"
    )


def _error_code(fn):
    """Call fn(); return its error code. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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


# Network teardown: resources in the VPC delete asynchronously and leave AWS-managed ENIs behind,
# so DeleteSubnet / DeleteSecurityGroup / DeleteVpc can fail with DependencyViolation. Wait (one
# window shared by a check's network deletes) for the ENIs, retrying that error, then raise.
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
