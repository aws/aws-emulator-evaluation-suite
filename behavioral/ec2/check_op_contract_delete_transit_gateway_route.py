"""op-contract-deleteTransitGatewayRoute."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteTransitGatewayRoute"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTransitGatewayRoute removes a static route from a route table; deleting it again,
    or deleting a CIDR that was never created, both -> NotFound."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgwrt-")
    cidr = "10.215.99.0/24"

    tgw_id = _create_tgw(ctx, ec2, name)
    route_table_id = _create_route_table(ctx, ec2, tgw_id, name)

    created = _retry_on_incorrect_state(
        lambda: ec2.create_transit_gateway_route(
            TransitGatewayRouteTableId=route_table_id,
            DestinationCidrBlock=cidr,
            Blackhole=True,
        )
    )
    assert created["Route"]["State"] in ("pending", "active", "blackhole"), created["Route"]

    # The route table's search index can lag a beat behind CreateTransitGatewayRoute's
    # synchronous response, so poll for the newly created route to become visible instead
    # of asserting on the very next read.
    routes = _poll(
        lambda: ec2.search_transit_gateway_routes(
            TransitGatewayRouteTableId=route_table_id,
            Filters=[{"Name": "route-search.exact-match", "Values": [cidr]}],
        )["Routes"],
        lambda rs: any(r["DestinationCidrBlock"] == cidr for r in rs),
        timeout_s=60.0,
    )
    assert any(r["DestinationCidrBlock"] == cidr for r in routes), routes

    delete_resp = ec2.delete_transit_gateway_route(
        TransitGatewayRouteTableId=route_table_id, DestinationCidrBlock=cidr
    )
    assert delete_resp["Route"]["DestinationCidrBlock"] == cidr, delete_resp["Route"]
    assert delete_resp["Route"]["State"] == "deleted", delete_resp["Route"]

    routes_after = _poll(
        lambda: ec2.search_transit_gateway_routes(
            TransitGatewayRouteTableId=route_table_id,
            Filters=[{"Name": "route-search.exact-match", "Values": [cidr]}],
        )["Routes"],
        lambda rs: not any(r["DestinationCidrBlock"] == cidr for r in rs),
        timeout_s=60.0,
    )
    assert not any(r["DestinationCidrBlock"] == cidr for r in routes_after), routes_after

    # The route this check just deleted must genuinely be gone: deleting it again is a
    # mutation on a dead id, not a repeat of the first delete's effect.
    double_delete = _error(
        lambda: ec2.delete_transit_gateway_route(
            TransitGatewayRouteTableId=route_table_id, DestinationCidrBlock=cidr
        )
    )
    assert double_delete["Code"] == "InvalidRoute.NotFound", double_delete
    assert double_delete.get("Message") == f"Route {cidr} does not exists in Transit Gateway Route Table {route_table_id}.", double_delete

    # Distinct boundary: the route table exists, but this exact CIDR was never created in it.
    never_created_cidr = "192.0.2.0/24"
    error = _error(
        lambda: ec2.delete_transit_gateway_route(
            TransitGatewayRouteTableId=route_table_id, DestinationCidrBlock=never_created_cidr
        )
    )
    assert error["Code"] == "InvalidRoute.NotFound", error
    assert error.get("Message") == f"Route {never_created_cidr} does not exists in Transit Gateway Route Table {route_table_id}.", error


def _poll(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn() and return its botocore Error dict; a call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _retry_on_incorrect_state(fn, timeout_s=180.0, interval_s=10.0):
    """A transit gateway route table that just reported describe-state "available" can
    still briefly reject dependent operations (e.g. CreateTransitGatewayRoute) with
    IncorrectState while the backend finishes propagating that state internally. Poll
    through that narrow window instead of treating it as fatal."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "IncorrectState":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _retry_on_tgw_limit(ec2, fn, timeout_s=1500.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TransitGatewayLimitExceeded" or time.monotonic() >= deadline:
                raise
            _reclaim_stale_tgws(ec2)
            time.sleep(interval_s)


def _reclaim_stale_tgws(ec2, min_age_s=1200.0):
    """Best-effort: free account TGW quota tied up by transit gateways THIS SAME
    self-contained suite created and failed to tear down (e.g. an earlier check in the
    same run that crashed/timed out before its own cleanup ran). Only ever deletes an
    "available" TGW carrying this suite's Name-tag prefix, with no live attachment, AND
    old enough (well beyond any single check's own timeout budget) that it cannot be a
    TGW that a concurrently-running check just created and is still actively wiring up
    (e.g. attaching a route table to, which this reclaim doesn't otherwise see) -- so it
    can't yank a resource out from under a check that's mid-flight."""
    try:
        tgws = ec2.describe_transit_gateways(Filters=[{"Name": "state", "Values": ["available"]}])[
            "TransitGateways"
        ]
    except ClientError:
        return
    now = datetime.now(timezone.utc)
    for tgw in tgws:
        name_tag = next((t["Value"] for t in tgw.get("Tags", []) if t["Key"] == "Name"), "")
        if not name_tag.startswith("sim2real-behav-"):
            continue
        creation_time = tgw.get("CreationTime")
        if creation_time is not None and (now - creation_time).total_seconds() < min_age_s:
            continue
        tgw_id = tgw["TransitGatewayId"]
        try:
            live = ec2.describe_transit_gateway_attachments(
                Filters=[
                    {"Name": "transit-gateway-id", "Values": [tgw_id]},
                    {
                        "Name": "state",
                        "Values": [
                            "available", "pending", "pendingAcceptance", "modifying",
                            "initiatingRequest", "rollingBack",
                        ],
                    },
                ]
            )["TransitGatewayAttachments"]
        except ClientError:
            continue
        if live:
            continue
        try:
            ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
        except ClientError:
            pass


def _create_tgw(ctx, ec2, name):
    created = _retry_on_tgw_limit(
        ec2,
        lambda: ec2.create_transit_gateway(
            Description=name,
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



def _create_route_table(ctx, ec2, tgw_id, name):
    created = ec2.create_transit_gateway_route_table(
        TransitGatewayId=tgw_id,
        TagSpecifications=[{"ResourceType": "transit-gateway-route-table", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    route_table_id = created["TransitGatewayRouteTable"]["TransitGatewayRouteTableId"]
    ctx.on_cleanup(
        lambda: _best_effort(lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=route_table_id))
    )
    # A freshly created route table is briefly in "pending" state; creating a route against it
    # before AWS finishes provisioning it is rejected with IncorrectState.
    _poll(
        lambda: ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[route_table_id])[
            "TransitGatewayRouteTables"
        ][0]["State"],
        lambda s: s == "available",
        timeout_s=120.0,
    )
    return route_table_id


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidRouteTableID.NotFound",
            "InvalidTransitGatewayID.NotFound",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
