"""op-contract-disable-route-server-propagation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-disable-route-server-propagation"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisableRouteServerPropagation on an enabled route-table propagation transitions it and
    drops it from GetRouteServerPropagations; DryRun returns the permission-check result."""
    ec2 = ctx.client("ec2")

    # The route table lives in the run's shared network: no VPC of the check's own to create.
    vpc_id = ctx.network().vpc_id

    route_table_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{
            "ResourceType": "route-table",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-rtb-")}],
        }],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=route_table_id))

    route_server_id = ec2.create_route_server(
        AmazonSideAsn=64512,
        PersistRoutes="disable",
        TagSpecifications=[{
            "ResourceType": "route-server",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-rs-")}],
        }],
    )["RouteServer"]["RouteServerId"]
    # ONE consolidated, WAITING teardown (see _teardown_route_server):
    # the per-resource cleanups this replaces did not wait for the
    # previous async delete, so every one of them failed in turn.
    ctx.on_cleanup(lambda: _teardown_route_server(ec2, route_server_id))

    ec2.associate_route_server(RouteServerId=route_server_id, VpcId=vpc_id)

    _poll_until(
        lambda: _association_state(ec2, route_server_id, vpc_id),
        lambda s: s == "associated",
        timeout_s=60.0,
    )

    enable_resp = ec2.enable_route_server_propagation(
        RouteServerId=route_server_id, RouteTableId=route_table_id
    )
    assert enable_resp["RouteServerPropagation"]["State"] in ("pending", "available")

    _poll_until(
        lambda: _propagation_state(ec2, route_server_id, route_table_id),
        lambda s: s == "available",
        timeout_s=60.0,
    )

    disable_resp = ec2.disable_route_server_propagation(
        RouteServerId=route_server_id, RouteTableId=route_table_id
    )
    assert disable_resp["RouteServerPropagation"]["State"] in ("deleting", "available")

    final_state = _poll_until(
        lambda: _propagation_state(ec2, route_server_id, route_table_id),
        lambda s: s is None,
        timeout_s=60.0,
    )
    assert final_state is None, f"propagation still present after disable: {final_state}"

    code, message = _client_error(lambda: ec2.disable_route_server_propagation(
        RouteServerId=route_server_id, RouteTableId=route_table_id, DryRun=True
    ))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {message!r}"
    )


# ===== helpers =====
def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because a
    target ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    return result


def _association_state(ec2, route_server_id, vpc_id):
    # The real EC2 API exposes these as Get* operations (GetRouteServerAssociations /
    # GetRouteServerPropagations), not Describe* — there is no
    # describe_route_server_associations/describe_route_server_propagations on the client.
    resp = ec2.get_route_server_associations(RouteServerId=route_server_id)
    for assoc in resp.get("RouteServerAssociations", []):
        if assoc.get("VpcId") == vpc_id:
            return assoc.get("State")
    return None


def _propagation_state(ec2, route_server_id, route_table_id):
    resp = ec2.get_route_server_propagations(RouteServerId=route_server_id)
    for prop in resp.get("RouteServerPropagations", []):
        if prop.get("RouteTableId") == route_table_id:
            return prop.get("State")
    return None


# ===== route-server teardown (self-contained) =====
# Route-server deletes are ASYNC and strictly ordered: peers block their endpoint, an
# endpoint's in-use ENI blocks DisassociateRouteServer (and DeleteSubnet/DeleteVpc), and an
# association blocks DeleteRouteServer. So the teardown retries whole passes under one shared
# budget instead of walking the chain once -- a single pass strands everything downstream of
# the first step that is still settling, and _rs_call swallows the rejection, so the leak is
# silent.
# Within the suite cleanup budget, leaving room for the check's network deletes.
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
    for. Filtering them out here is exactly what stranded route servers before -- discovery saw
    "nothing left to delete", skipped the wait, and DeleteRouteServerEndpoint was then rejected
    because the peer was still going away.
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
    endpoint ENI also holds a VPC against the account's per-Region VPC quota, so a silent
    leak here costs money and can exhaust that quota.
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
