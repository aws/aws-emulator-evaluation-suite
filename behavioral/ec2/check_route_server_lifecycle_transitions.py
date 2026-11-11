"""route-server-lifecycle-transitions."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "route-server-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRouteServer with DryRun fails with DryRunOperation and creates nothing; the real call reaches
    "available", AssociateRouteServer reports "associated", and after disassociate and delete the route
    server is absent or "deleted"."""
    ec2 = ctx.client("ec2")

    vpc = ec2.create_vpc(CidrBlock="10.231.0.0/16")["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    name = ctx.unique_name("sim2real-rs-")

    # --- DryRun negative: must be rejected, must not create a route server ---
    err = _error(
        lambda: ec2.create_route_server(AmazonSideAsn=64512, DryRun=True)
    )
    assert err["Code"] == "DryRunOperation", f"expected DryRunOperation, got {err!r}"
    assert err.get("Message") == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected message: {err.get('Message')!r}"
    )
    existing = ec2.describe_route_servers(
        Filters=[{"Name": "tag:Name", "Values": [name]}]
    )["RouteServers"]
    assert existing == [], f"expected no route server created under DryRun, found {existing!r}"

    # --- Positive control: the real create succeeds ---
    rs = ec2.create_route_server(
        AmazonSideAsn=64512,
        TagSpecifications=[
            {"ResourceType": "route-server", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["RouteServer"]
    rs_id = rs["RouteServerId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_route_server(RouteServerId=rs_id)))
    assert rs["State"] in ("pending", "available"), f"unexpected initial state {rs['State']!r}"

    rs = _poll_until(
        lambda: ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"][0],
        lambda r: r["State"] == "available",
        timeout_s=180,
    )
    assert rs["State"] == "available", f"expected available, got {rs['State']!r}"

    # --- Associate with the VPC, transitions to associated ---
    ec2.associate_route_server(RouteServerId=rs_id, VpcId=vpc_id)
    assoc = _poll_until(
        lambda: next(
            (a for a in _get_associations_safe(ec2, rs_id) if a["VpcId"] == vpc_id),
            None,
        ),
        lambda a: a is not None and a["State"] == "associated",
        timeout_s=180,
    )
    assert assoc["State"] == "associated", f"expected associated, got {assoc['State']!r}"

    # --- Disassociate, association disappears from the active set ---
    ec2.disassociate_route_server(RouteServerId=rs_id, VpcId=vpc_id)
    _poll_until(
        lambda: [
            a for a in _get_associations_safe(ec2, rs_id) if a["VpcId"] == vpc_id
        ],
        lambda lst: lst == [],
        timeout_s=180,
    )

    # --- Delete drives the route server to deleted ---
    ec2.delete_route_server(RouteServerId=rs_id)
    final = _poll_until(
        lambda: ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"],
        lambda lst: lst == [] or lst[0]["State"] == "deleted",
        timeout_s=180,
    )
    assert final == [] or final[0]["State"] == "deleted", (
        f"expected the route server gone or deleted, got {final!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidRouteServerId.NotFound",
            "InvalidVpcID.NotFound",
        ):
            raise


def _error(fn):
    """Call fn(); return its ClientError Error dict. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
