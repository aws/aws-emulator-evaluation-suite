"""op-contract-create-route-server."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-create-route-server"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRouteServer with AmazonSideAsn 64512 creates a route server that echoes that ASN and reaches
    available; AmazonSideAsn 4294967296 fails with InvalidParameterValue and its exact message."""
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-rscontract-")
    resp = ec2.create_route_server(
        AmazonSideAsn=64512,
        TagSpecifications=[{"ResourceType": "route-server", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    rs = resp["RouteServer"]
    rs_id = rs["RouteServerId"]
    # One teardown that waits for each asynchronous delete before the next one.
    ctx.on_cleanup(lambda: _teardown_route_server(ec2, rs_id))

    assert rs["AmazonSideAsn"] == 64512, f"expected AmazonSideAsn 64512, got {rs['AmazonSideAsn']!r}"
    assert rs["State"] in ("pending", "available"), f"expected pending/available, got {rs['State']!r}"

    final_state = _poll_until(
        lambda: ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"][0]["State"],
        lambda s: s == "available",
        timeout_s=90.0,
        interval_s=3.0,
        description=f"route server {rs_id} reaching available",
    )
    assert final_state == "available", f"route server never reached available, got {final_state!r}"

    # Error boundary: AmazonSideAsn must be a 32-bit ASN (0-4294967295); one above the maximum
    # is out of range and rejected (0 itself is accepted by the service).
    code, message = _error(lambda: ec2.create_route_server(AmazonSideAsn=4294967296))
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == "Value (AmazonSideAsn) for 4294967296 is invalid.", message


# ===== helpers =====
def _error(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises: accepting input real
    AWS refuses is a distinct failure from returning the wrong error code."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


# Route-server deletes are asynchronous and ordered: peers block their endpoint, an endpoint's ENI
# blocks DisassociateRouteServer, and an association blocks DeleteRouteServer, so the teardown
# retries whole passes under one shared budget and raises if a route server is still live.
_RS_TEARDOWN_BUDGET_S = 840.0
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
    """VPC associations still holding the route server: an association disappears once disassociated
    (no terminal state), and GetRouteServerAssociations then raises
    InvalidRouteServerId.NotAssociated, which _rs_call turns into {} meaning none left."""
    return _rs_call(ec2.get_route_server_associations, RouteServerId=route_server_id).get(
        "RouteServerAssociations", []
    )


def _teardown_route_server(ec2, route_server_id: str) -> None:
    """Delete a route server and everything attached to it, waiting at each step; discovery-based,
    so it removes whatever peers, endpoints, propagations and associations exist however far the
    check got, since a leaked route server is billed hourly and its endpoint ENI holds a VPC."""
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
