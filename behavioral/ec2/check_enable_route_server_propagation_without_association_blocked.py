"""enable-route-server-propagation-without-association-blocked."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "enable-route-server-propagation-without-association-blocked"
GROUP = "overly-permissive"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EnableRouteServerPropagation is rejected for a route table whose VPC is not associated with
    the route server, and succeeds for that same route table once the VPC is associated."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-rsprop-")

    vpc_id, created_vpc = _get_or_create_test_vpc(ec2, ctx)
    if created_vpc:
        ctx.on_cleanup(lambda: _ignore_error(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    rt_id = ec2.create_route_table(VpcId=vpc_id, TagSpecifications=_tag_spec("route-table", name))[
        "RouteTable"
    ]["RouteTableId"]
    ctx.on_cleanup(lambda: _ignore_error(lambda: ec2.delete_route_table(RouteTableId=rt_id)))

    rs_id = ec2.create_route_server(
        AmazonSideAsn=64512, TagSpecifications=_tag_spec("route-server", name)
    )["RouteServer"]["RouteServerId"]
    # ONE consolidated, discovery-based teardown (see _teardown_route_server)
    # that waits for each async delete before the next step.
    ctx.on_cleanup(lambda: _teardown_route_server(ec2, rs_id))

    def _rs_state():
        return ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"][0]["State"]

    _poll_until(_rs_state, lambda s: s == "available", timeout_s=120, interval_s=3)

    # ---- Negative: the route table's VPC is not associated with the route server ----
    code, message = _error(lambda: ec2.enable_route_server_propagation(RouteServerId=rs_id, RouteTableId=rt_id))
    assert code == "InvalidRouteServerId.NotAssociated", f"expected InvalidRouteServerId.NotAssociated, got {code!r}"
    assert message == f"Route Server {rs_id} is not associated with a VPC.", f"unexpected InvalidRouteServerId.NotAssociated message: {message!r}"

    # Effect absence: no propagation was created for this route table.
    def _prop_state():
        try:
            props = ec2.get_route_server_propagations(RouteServerId=rs_id, RouteTableId=rt_id)[
                "RouteServerPropagations"
            ]
        except Exception as exc:
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError) and exc.response["Error"]["Code"] == "InvalidRouteServerId.NotPropagated":
                return None
            raise
        for p in props:
            if p["RouteTableId"] == rt_id:
                return p["State"]
        return None

    state_after_reject = _prop_state()
    assert state_after_reject is None, f"expected no propagation after rejection, got state {state_after_reject!r}"

    # ---- Positive control: associate the VPC, then propagation can be enabled ----
    ec2.associate_route_server(RouteServerId=rs_id, VpcId=vpc_id)

    def _assoc_state():
        assocs = ec2.get_route_server_associations(RouteServerId=rs_id)["RouteServerAssociations"]
        for a in assocs:
            if a["VpcId"] == vpc_id:
                return a["State"]
        return None

    _poll_until(_assoc_state, lambda s: s == "associated", timeout_s=120, interval_s=3)

    ec2.enable_route_server_propagation(RouteServerId=rs_id, RouteTableId=rt_id)
    _poll_until(_prop_state, lambda s: s == "available", timeout_s=120, interval_s=3)


# ===== helpers (self-contained) =====

def _tag_spec(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected success raises, because
    a target accepting what real AWS refuses must not read as a plain code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _ignore_error(fn: Callable[[], Any]) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidRouteTableID.NotFound",
            "InvalidVpcID.NotFound",
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


def _get_or_create_test_vpc(ec2, ctx) -> tuple[str, bool]:
    """Return (vpc_id, created) -- reusing the run's shared network when one exists
    (no quota cost, and nothing for this check to delete afterwards) and only
    creating a dedicated VPC when there isn't one. The create retries
    VpcLimitExceeded every 2 s for up to 300 s, while concurrent checks release
    the VPC quota."""
    from botocore.exceptions import ClientError

    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        return default_vpcs[0]["VpcId"], False

    def _do_create():
        return ec2.create_vpc(
            CidrBlock="10.91.0.0/16",
            TagSpecifications=_tag_spec("vpc", ctx.unique_name("sim2real-rsprop-vpc-")),
        )["Vpc"]["VpcId"]

    # The VPC quota can be held by checks running concurrently; wait for them to release it.
    deadline = time.monotonic() + 300.0
    while True:
        try:
            return _do_create(), True
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "VpcLimitExceeded" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


# ===== route-server teardown (self-contained) =====
# Route-server deletes are ASYNC and strictly ordered: peers block their endpoint, an
# endpoint's in-use ENI blocks DisassociateRouteServer (and DeleteSubnet/DeleteVpc), and an
# association blocks DeleteRouteServer. So the teardown retries whole passes under one shared
# budget instead of walking the chain once -- a single pass strands everything downstream of
# the first step that is still settling. The budget leaves room for the VPC deletes in the
# suite's cleanup budget; a route server still live at its end raises.
_RS_TEARDOWN_BUDGET_S = 600.0
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
    endpoint ENI holds a VPC slot against the account's per-Region VPC quota, so a leak costs
    money and can block later VPC-creating checks.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
