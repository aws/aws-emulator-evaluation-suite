"""op-contract-delete-route-server-endpoint."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-delete-route-server-endpoint"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRouteServerEndpoint: success transitions state to deleting/gone; DryRun rejects."""

    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(CidrBlock="10.91.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    _tag(ec2, vpc_id, ctx.unique_name("sim2real-behav-rse-vpc-"))

    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.91.1.0/24")["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    try:
        route_server_id = ec2.create_route_server(AmazonSideAsn=4200000001)["RouteServer"][
            "RouteServerId"
        ]
    except Exception as exc:  # pragma: no cover - environment-dependent
        raise AssertionError(f"CreateRouteServer unavailable: {exc}") from exc
    # ONE consolidated, WAITING teardown (see _teardown_route_server):
    # the per-resource cleanups this replaces did not wait for the
    # previous async delete, so every one of them failed in turn.
    ctx.on_cleanup(lambda: _teardown_route_server(ec2, route_server_id))

    # The route server itself must finish provisioning (State == "available") before an
    # association request will actually be processed; associating too early leaves the
    # association list empty indefinitely rather than surfacing an "associating" state.
    _poll_until(
        lambda: ec2.describe_route_servers(RouteServerIds=[route_server_id])["RouteServers"][0][
            "State"
        ],
        lambda state: state == "available",
        timeout_s=300,
    )

    ec2.associate_route_server(RouteServerId=route_server_id, VpcId=vpc_id)

    _poll_until(
        lambda: _association_state(ec2, route_server_id, vpc_id),
        lambda state: state == "associated",
        timeout_s=300,
    )

    endpoint = ec2.create_route_server_endpoint(
        RouteServerId=route_server_id, SubnetId=subnet_id
    )["RouteServerEndpoint"]
    endpoint_id = endpoint["RouteServerEndpointId"]

    _poll_until(
        lambda: ec2.describe_route_server_endpoints(RouteServerEndpointIds=[endpoint_id])[
            "RouteServerEndpoints"
        ][0]["State"],
        lambda state: state == "available",
        timeout_s=120,
    )

    # Error boundary: DryRun on a valid delete request must short-circuit with DryRunOperation.
    code, msg = _client_error(
        lambda: ec2.delete_route_server_endpoint(RouteServerEndpointId=endpoint_id, DryRun=True)
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    expected_msg = "Request would have succeeded, but DryRun flag is set."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Success path: real delete transitions state and is eventually reflected as gone.
    resp = ec2.delete_route_server_endpoint(RouteServerEndpointId=endpoint_id)
    got_id = resp["RouteServerEndpoint"]["RouteServerEndpointId"]
    assert got_id == endpoint_id, f"expected {endpoint_id!r}, got {got_id!r}"
    got_state = resp["RouteServerEndpoint"]["State"]
    assert got_state in ("deleting", "deleted"), f"expected deleting/deleted, got {got_state!r}"

    final_state = _poll_until(
        lambda: ec2.describe_route_server_endpoints(RouteServerEndpointIds=[endpoint_id])[
            "RouteServerEndpoints"
        ][0]["State"],
        lambda state: state == "deleted",
        timeout_s=180,
    )
    assert final_state == "deleted", f"expected deleted, got {final_state!r}"

    # Gone is also unusable: a mutation on the now-deleted id is rejected, not silently
    # accepted. Unlike an unknown id (InvalidRouteServerEndpointId.NotFound), a known id
    # that has reached a terminal state is rejected as IncorrectState.
    dead_code, dead_msg = _client_error(
        lambda: ec2.delete_route_server_endpoint(RouteServerEndpointId=endpoint_id)
    )
    assert dead_code == "IncorrectState", f"expected IncorrectState, got {dead_code!r}"
    expected_msg = f"Route Server Endpoint {endpoint_id} is in an invalid state."
    assert dead_msg == expected_msg, f"expected message {expected_msg!r}, got {dead_msg!r}"


# ===== helpers =====
def _tag(ec2: Any, resource_id: str, name: str) -> None:
    ec2.create_tags(Resources=[resource_id], Tags=[{"Key": "Name", "Value": name}])


def _association_state(ec2: Any, route_server_id: str, vpc_id: str) -> str | None:
    # NOTE: the read API for route server associations is GetRouteServerAssociations,
    # not DescribeRouteServerAssociations (which does not exist on real AWS and raises
    # AttributeError on the client, silently swallowed by _poll_until's except-clause).
    resp = ec2.get_route_server_associations(RouteServerId=route_server_id)
    for assoc in resp.get("RouteServerAssociations", []):
        if assoc.get("VpcId") == vpc_id:
            return assoc.get("State")
    return None


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 3.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except Exception:
            last = None
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


# ===== route-server teardown (self-contained) =====
# Route-server deletes are ASYNC and strictly ordered: peers block their endpoint, an
# endpoint's in-use ENI blocks DisassociateRouteServer (and DeleteSubnet/DeleteVpc), and an
# association blocks DeleteRouteServer. So the teardown retries whole passes under one shared
# budget instead of walking the chain once -- a single pass strands everything downstream of
# the first step that is still settling. A route server still live at the end of the budget
# raises.
_RS_TEARDOWN_BUDGET_S = 570.0
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
    endpoint ENI also holds a VPC against the account's per-Region VPC quota, so a silent
    leak here costs money and can exhaust that quota.
    """
    from botocore.exceptions import ClientError

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


# AWS-managed ENIs (endpoints, load balancers, instances) leave a VPC asynchronously after their
# owner's delete returns, so DeleteSubnet/DeleteSecurityGroup/DeleteVpc can fail with
# DependencyViolation. Wait (bounded) for the ENIs to go, retry inside the same window, and raise
# naming any ENIs still attached. Teardown-only: run() never calls this.
_NET_TEARDOWN_S = 300.0
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
