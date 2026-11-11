"""disassociate-route-server-unassociated-vpc-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "disassociate-route-server-unassociated-vpc-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateRouteServer succeeds for a real association, but is rejected when the
    RouteServerId/VpcId pair given was never associated (both resources exist, the pairing
    does not)."""
    ec2 = ctx.client("ec2")

    vpc1_id = _create_or_adopt_vpc(ec2, ctx, "10.211.0.0/16", ctx.unique_name("sim2real-rsvpc1-"))
    vpc2_id = _create_or_adopt_vpc(ec2, ctx, "10.212.0.0/16", ctx.unique_name("sim2real-rsvpc2-"), exclude=vpc1_id)

    rs = ec2.create_route_server(
        AmazonSideAsn=64512,
        PersistRoutes="disable",
        TagSpecifications=[_tag_spec("route-server", ctx.unique_name("sim2real-rs-"))],
    )["RouteServer"]
    rs_id = rs["RouteServerId"]
    # ONE consolidated teardown (see _teardown_route_server) that waits for
    # each async delete before the next step.
    ctx.on_cleanup(lambda: _teardown_route_server(ec2, rs_id))

    ec2.associate_route_server(RouteServerId=rs_id, VpcId=vpc1_id)

    def _assoc_state():
        # The boto3/EC2 API for route server associations is GetRouteServerAssociations
        # (there is no DescribeRouteServerAssociations operation).
        resp = ec2.get_route_server_associations(RouteServerId=rs_id)
        assocs = resp.get("RouteServerAssociations", [])
        return assocs[0]["State"] if assocs else None

    _poll_until(_assoc_state, lambda s: s in ("associated", "associating"), timeout_s=90.0, interval_s=5.0)

    # NEGATIVE: rs_id and vpc2_id are both real, existing resources, but they were never
    # associated with each other -- this must be rejected distinctly from a bogus-ID case.
    code, message = _error(lambda: ec2.disassociate_route_server(RouteServerId=rs_id, VpcId=vpc2_id))
    assert code == "InvalidRouteServerId.NotAssociated", f"unexpected error code for unassociated pairing: {code}"
    assert message == f"Route Server {rs_id} is not associated with VPC {vpc2_id}.", f"unexpected message for unassociated pairing: {message!r}"

    # Effect absence: the rejected call left the real (vpc1) association untouched -- an
    # independent read, not a re-inspection of the rejected call's own (absent) response.
    after_reject = _get_associations(ec2, rs_id)
    vpc1_after_reject = next((a for a in after_reject if a["VpcId"] == vpc1_id), None)
    assert vpc1_after_reject is not None, (
        f"expected vpc1 association to survive the rejected vpc2 disassociate, got {after_reject!r}"
    )
    assert vpc1_after_reject["State"] in ("associated", "associating"), (
        f"expected vpc1 association untouched by the rejected call, "
        f"got state={vpc1_after_reject['State']!r}"
    )

    # POSITIVE: disassociating the real association succeeds.
    resp = ec2.disassociate_route_server(RouteServerId=rs_id, VpcId=vpc1_id)
    association = resp["RouteServerAssociation"]
    assert association["RouteServerId"] == rs_id, (
        f"expected RouteServerId {rs_id!r} in disassociate response, got {association.get('RouteServerId')!r}"
    )
    assert association["VpcId"] == vpc1_id, (
        f"expected VpcId {vpc1_id!r} in disassociate response, got {association.get('VpcId')!r}"
    )
    assert association["State"] in ("disassociating", "disassociated"), (
        f"expected disassociating/disassociated in disassociate response, got {association['State']!r}"
    )

    # Terminal read: an INDEPENDENT read (GetRouteServerAssociations, not the mutating call's
    # own echoed response) proves the disassociation actually took effect. Once the last
    # association is gone the operation RAISES InvalidRouteServerId.NotAssociated instead of
    # returning an empty list (see _get_associations), so "absent" is a valid terminal reading.
    def _vpc1_state():
        for a in _get_associations(ec2, rs_id):
            if a["VpcId"] == vpc1_id:
                return a["State"]
        return "absent"

    _poll_until(_vpc1_state, lambda s: s in ("disassociating", "absent"), timeout_s=90.0, interval_s=5.0)


# ===== helpers =====
def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_or_adopt_vpc(ec2, ctx, cidr, name, exclude=None):
    """Create a VPC for the test and register its delete."""
    vpc = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


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


def _get_associations(ec2, route_server_id):
    """Independent read of a route server's VPC associations.

    Once the last association is gone, GetRouteServerAssociations RAISES
    InvalidRouteServerId.NotAssociated instead of returning an empty list (observed against
    real AWS, consistent with the same quirk documented in this service's other route-server
    checks) -- treat that specific code as "no associations", and let anything else propagate
    so a genuine failure is never mistaken for absence.
    """
    from botocore.exceptions import ClientError

    try:
        return ec2.get_route_server_associations(RouteServerId=route_server_id).get(
            "RouteServerAssociations", []
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvalidRouteServerId.NotAssociated":
            return []
        raise


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {last!r}")


# ===== route-server teardown (self-contained) =====
# Route-server deletes are ASYNC and strictly ordered: peers block their endpoint, an
# endpoint's in-use ENI blocks DisassociateRouteServer (and DeleteSubnet/DeleteVpc), and an
# association blocks DeleteRouteServer. So the teardown retries whole passes under one shared
# budget instead of walking the chain once -- a single pass strands everything downstream of
# the first step that is still settling. _rs_call tolerates only not-found codes and the
# in-progress refusals the next pass retries; a route server still live at the budget raises.
# The budget fits the suite's 900 s cleanup budget with room for the VPC deletes.
_RS_TEARDOWN_BUDGET_S = 600.0
# Terminal states, from the botocore enums: peers are pending|available|deleting|deleted|
# failing|failed, endpoints add delete-failed (also terminal -- waiting out the budget on it
# would only stall the teardown).
_RS_PEER_TERMINAL = ("deleted", "failed")
_RS_ENDPOINT_TERMINAL = ("deleted", "delete-failed", "failed")
# Already gone: NotAssociated / NotPropagated are what the association / propagation reads and
# undo calls answer once nothing is left.
_RS_GONE = ("InvalidRouteServerId.NotAssociated", "InvalidRouteServerId.NotPropagated")
# Refusals while an upstream delete is still settling; the next pass retries them.
_RS_SETTLING = ("IncorrectState", "DependencyViolation")


def _rs_call(fn, **kwargs):
    """Teardown call: {} on a not-found code or a settling refusal (retried by the next pass);
    any other failure raises."""
    from botocore.exceptions import ClientError

    try:
        return fn(**kwargs) or {}
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code.endswith(".NotFound") or code in _RS_GONE or code in _RS_SETTLING:
            return {}
        raise


def _rs_wait(remaining, *, deadline, interval_s=2.0) -> None:
    while time.monotonic() < deadline:
        if not remaining():
            return
        time.sleep(interval_s)


def _rs_peers(ec2, route_server_id):
    """Peers of this route server that still block deleting its endpoint.

    Deliberately includes peers already in "deleting": they are what the next step has to WAIT
    for. DeleteRouteServerEndpoint is rejected while a peer is still going away.
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
    endpoint ENI blocks the subnet and VPC deletes, so a leak here costs money and breaks later
    VPC-dependent runs.
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
                f"route server {route_server_id} still {live!r} after {_RS_TEARDOWN_BUDGET_S:.0f}s"
            )
        # Guard against a zero-delay spin: if the route server is stuck refusing delete with
        # nothing left to wait on, every _rs_wait above returns instantly, so pause before the
        # next pass to avoid hammering the EC2 API into throttling.
        time.sleep(min(2.0, max(0.0, deadline - time.monotonic())))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
