"""op-contract-get-route-server-associations."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "op-contract-get-route-server-associations"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRouteServerAssociations reflects a real VPC association through its state
    machine (associating -> associated); a nonexistent route server ID is NotFound."""
    ec2 = ctx.client("ec2")

    # Uses the run's shared network VPC; the association does not need an exclusive VPC.
    vpc_id = _get_default_vpc(ec2, ctx=ctx)

    rs = ec2.create_route_server(
        AmazonSideAsn=65000,
        TagSpecifications=[{"ResourceType": "route-server", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-rs-")}]}],
    )["RouteServer"]
    route_server_id = rs["RouteServerId"]

    # One waiting teardown (see _teardown_route_server): a route server bills hourly, and its
    # association with the shared VPC is not removed by deleting any VPC of this check.
    ctx.on_cleanup(lambda: _teardown_route_server(ec2, route_server_id))

    ec2.associate_route_server(RouteServerId=route_server_id, VpcId=vpc_id)

    # success-path contract: the association reaches "associated" for the exact VPC.
    associations = _poll_until(
        lambda: ec2.get_route_server_associations(RouteServerId=route_server_id)["RouteServerAssociations"],
        lambda assocs: any(a["VpcId"] == vpc_id and a["State"] == "associated" for a in assocs),
        timeout_s=180,
        interval_s=5,
    )
    match = next(a for a in associations if a["VpcId"] == vpc_id)
    assert match["RouteServerId"] == route_server_id, (
        f"expected association RouteServerId {route_server_id!r}, got {match['RouteServerId']!r}"
    )
    assert match["State"] == "associated", f"expected State 'associated', got {match['State']!r}"

    # error boundary: well-formed but nonexistent route server ID -> NotFound-class error.
    bogus_id = _bogus_id_like(route_server_id)
    code, message = _client_error(lambda: ec2.get_route_server_associations(RouteServerId=bogus_id))
    assert code == "InvalidRouteServerId.NotFound", f"unexpected error code: {code}"
    expected_message = f"The route-server ID '{bogus_id}' does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


# ===== helpers =====
def _get_default_vpc(ec2, *, ctx) -> str:
    """Return the run's shared network VPC id."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    return vpcs[0]["VpcId"]


def _client_error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _bogus_id_like(real_id: str) -> str:
    def repl(m):
        return "f" * len(m.group())
    bogus = re.sub(r"[0-9a-f]+$", repl, real_id)
    assert bogus != real_id, "could not derive a distinct bogus id"
    return bogus


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last result: {last!r}")


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
