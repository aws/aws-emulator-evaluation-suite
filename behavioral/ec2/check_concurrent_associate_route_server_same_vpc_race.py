"""concurrent-associate-route-server-same-vpc-race."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-associate-route-server-same-vpc-race"
GROUP = "concurrency"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two identical AssociateRouteServer calls for one (route server, VPC) pair at the same instant both succeed,
    as the call is idempotent, and leave exactly one association, never a duplicate."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-rsassocrace-")

    # The check creates its own VPC, as an account need not have a default one.
    vpc_id = _create_or_adopt_vpc(ec2, ctx, "10.219.0.0/16", name)

    rs_id = ec2.create_route_server(
        AmazonSideAsn=4200000102,
        TagSpecifications=_tag_spec("route-server", name),
    )["RouteServer"]["RouteServerId"]
    ctx.on_cleanup(lambda: ec2.delete_route_server(RouteServerId=rs_id))

    _poll_until(lambda: _rs_state(ec2, rs_id), lambda s: s == "available", timeout_s=120, interval_s=3)

    ctx.on_cleanup(lambda: _disassociate_and_wait(ec2, rs_id, vpc_id))

    barrier = threading.Barrier(2)

    def _associate():
        barrier.wait(timeout=30)
        try:
            ec2.associate_route_server(RouteServerId=rs_id, VpcId=vpc_id)
            return ("ok", None)
        except Exception as exc:
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError):
                return ("error", exc.response["Error"]["Code"])
            raise

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_associate)
        fut_b = pool.submit(_associate)
        result_a = fut_a.result()
        result_b = fut_b.result()

    results = [result_a, result_b]
    # AssociateRouteServer for an identical (route server, VPC) pair is idempotent, so both racing calls succeed.
    assert results == [("ok", None), ("ok", None)], f"expected both racing AssociateRouteServer calls to succeed, got {results}"

    _poll_until(
        lambda: _association_state(ec2, rs_id, vpc_id),
        lambda s: s == "associated",
        timeout_s=120,
        interval_s=5,
    )

    associations = [
        a for a in ec2.get_route_server_associations(RouteServerId=rs_id)["RouteServerAssociations"]
        if a["VpcId"] == vpc_id
    ]
    assert len(associations) == 1, f"expected exactly one association for the VPC, got {associations}"


def _tag_spec(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _create_or_adopt_vpc(ec2, ctx, cidr: str, name: str) -> str:
    """Create a VPC for the test and register its delete."""
    vpc_id = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=_tag_spec("vpc", name))["Vpc"][
        "VpcId"
    ]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


def _rs_state(ec2, rs_id: str):
    return ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"][0]["State"]


def _association_state(ec2, rs_id: str, vpc_id: str):
    from botocore.exceptions import ClientError

    try:
        associations = ec2.get_route_server_associations(RouteServerId=rs_id)["RouteServerAssociations"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvalidRouteServerId.NotAssociated":
            return None  # the route server has no VPC association left
        raise
    for a in associations:
        if a["VpcId"] == vpc_id:
            return a["State"]
    return None


def _disassociate_and_wait(ec2, rs_id: str, vpc_id: str) -> None:
    try:
        ec2.disassociate_route_server(RouteServerId=rs_id, VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidRouteServerId.NotAssociated",
            "InvalidVpcID.NotFound",
        ):
            raise
        return
    _poll_until(
        lambda: _association_state(ec2, rs_id, vpc_id),
        lambda s: s in (None, "disassociated"),
        timeout_s=120,
        interval_s=5,
    )


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
