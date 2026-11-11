"""op-contract-modify-route-server."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-modify-route-server"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyRouteServer: toggling SnsNotificationsEnabled is reflected on the route
    server, and an out-of-range PersistRoutesDuration (valid range is 1-5) is rejected."""
    ec2 = ctx.client("ec2")
    if not hasattr(ec2, "create_route_server"):
        raise AssertionError("botocore in this environment lacks VPC Route Server support")

    name = ctx.unique_name("sim2real-behav-rs-")
    created = ec2.create_route_server(
        AmazonSideAsn=64512,
        PersistRoutes="disable",
        SnsNotificationsEnabled=False,
        TagSpecifications=[_tag_spec("route-server", name)],
    )["RouteServer"]
    rs_id = created["RouteServerId"]
    # One waiting teardown (see _teardown_route_server) so a rejected delete does not leak the
    # route server.
    ctx.on_cleanup(lambda: _teardown_route_server(ec2, rs_id))

    rs = _poll_until(
        lambda: ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"][0],
        lambda r: r["State"] in ("available", "failed"),
        timeout_s=90,
    )
    assert rs["State"] == "available", f"route server failed to become available: {rs}"

    # success path
    modified = ec2.modify_route_server(RouteServerId=rs_id, SnsNotificationsEnabled=True)["RouteServer"]
    assert modified["SnsNotificationsEnabled"] is True, modified
    described = ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"][0]
    assert described["SnsNotificationsEnabled"] is True, described

    # positive control: a duration inside the 1-5 minute range is accepted on the SAME
    # wiring (PersistRoutes="enable" + PersistRoutesDuration) that the negative below
    # exercises. Without this, "rejects duration=10" is indistinguishable from "rejects
    # enabling persist-routes at all".
    enabled = ec2.modify_route_server(
        RouteServerId=rs_id, PersistRoutes="enable", PersistRoutesDuration=3
    )["RouteServer"]
    assert enabled["PersistRoutesDuration"] == 3, enabled
    described = ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"][0]
    assert described["PersistRoutesDuration"] == 3, described

    # error boundary: PersistRoutesDuration must be 1-5 minutes (always-invalid-input --
    # no restore leg, the value can never become valid)
    err, message = _error(
        lambda: ec2.modify_route_server(
            RouteServerId=rs_id, PersistRoutes="enable", PersistRoutesDuration=10
        )
    )
    assert err == "InvalidParameterValue", err
    assert message == "Persist routes time is invalid for this operation.", message

    # effect absent: the rejected call must not have overwritten the duration set by the
    # positive control, read independently
    described = ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"][0]
    assert described["PersistRoutesDuration"] == 3, described


# ===== helpers =====
def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


# ===== route-server teardown (self-contained) =====
# Route-server deletes are ASYNC and strictly ordered: peers block their endpoint, an
# endpoint's in-use ENI blocks DisassociateRouteServer (and DeleteSubnet/DeleteVpc), and an
# association blocks DeleteRouteServer. So the teardown retries whole passes under one shared
# budget instead of walking the chain once -- a single pass strands everything downstream of
# the first step that is still settling, and _rs_call swallows the rejection, so the leak is
# silent.
# Bounded so the teardown fits the suite cleanup budget.
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

    Includes peers in "deleting" because the endpoint delete must wait for them.
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
    endpoint ENI holds a VPC, so a leak costs money and can exhaust the VPC quota.
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
                f"route server {route_server_id} not deleted within {_RS_TEARDOWN_BUDGET_S}s: {live}"
            )
        # Guard against a zero-delay spin: if the route server is stuck refusing delete with
        # nothing left to wait on, every _rs_wait above returns instantly, so pause before the
        # next pass to avoid hammering the EC2 API into throttling.
        time.sleep(min(2.0, max(0.0, deadline - time.monotonic())))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
