"""associate-route-server-already-associated-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "associate-route-server-already-associated-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A route server associated with one VPC is refused a second VPC with InvalidRouteServerId.AlreadyAssociated
    and keeps its one association, while another route server associates with the first VPC, and
    disassociating frees it for the second."""
    ec2 = ctx.client("ec2")
    # Only the VPCs this check creates are deleted. At the VPC quota, create_vpc fails loudly:
    # an absent prerequisite is a FAIL.
    name = ctx.unique_name("sim2real-rsassoc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.217.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    other_vpc_id = ec2.create_vpc(
        CidrBlock="10.218.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=other_vpc_id))

    route_server_id = ec2.create_route_server(
        AmazonSideAsn=4200000001,
        TagSpecifications=[
            {"ResourceType": "route-server", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["RouteServer"]["RouteServerId"]
    ctx.on_cleanup(lambda: ec2.delete_route_server(RouteServerId=route_server_id))
    other_route_server_id = ec2.create_route_server(
        AmazonSideAsn=4200000002,
        TagSpecifications=[
            {"ResourceType": "route-server", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["RouteServer"]["RouteServerId"]
    ctx.on_cleanup(lambda: ec2.delete_route_server(RouteServerId=other_route_server_id))

    ec2.associate_route_server(RouteServerId=route_server_id, VpcId=vpc_id)
    ctx.on_cleanup(
        lambda: _disassociate_and_wait(ctx, route_server_id, vpc_id)
    )
    _poll_until(
        lambda: _association_state(ec2, route_server_id, vpc_id),
        lambda state: state == "associated",
        timeout_s=120,
        interval_s=5,
    )

    # Negative: the same route server, already associated with vpc_id,
    # is rejected when associated with a second, DIFFERENT vpc.
    code = _error_code(
        lambda: ec2.associate_route_server(RouteServerId=route_server_id, VpcId=other_vpc_id)
    )
    assert code == "InvalidRouteServerId.AlreadyAssociated", (
        f"expected InvalidRouteServerId.AlreadyAssociated, got {code!r}"
    )

    # Effect absence: the route server still has exactly one association,
    # and it is still the original vpc_id -- not the rejected other_vpc_id.
    associations = ec2.get_route_server_associations(RouteServerId=route_server_id)[
        "RouteServerAssociations"
    ]
    assert len(associations) == 1, (
        f"expected exactly 1 association for {route_server_id}, got {len(associations)}"
    )
    assert associations[0]["VpcId"] == vpc_id, (
        f"expected the surviving association to still be {vpc_id}, got {associations[0]['VpcId']}"
    )
    other_vpc_state = _association_state(ec2, route_server_id, other_vpc_id)
    assert other_vpc_state is None, (
        f"expected no association between {route_server_id} and the rejected {other_vpc_id}, "
        f"got state {other_vpc_state!r}"
    )

    # Positive control: another route server associates with vpc_id while route_server_id still
    # holds it, so the refusal is route_server_id's one-VPC limit, not a block on vpc_id.
    ec2.associate_route_server(RouteServerId=other_route_server_id, VpcId=vpc_id)
    ctx.on_cleanup(
        lambda: _disassociate_and_wait(ctx, other_route_server_id, vpc_id)
    )
    _poll_until(
        lambda: _association_state(ec2, other_route_server_id, vpc_id),
        lambda state: state == "associated",
        timeout_s=120,
        interval_s=5,
    )

    # Restore: disassociating vpc_id frees route_server_id, and it then
    # associates fine with the VPC it was rejected from a moment ago.
    ec2.disassociate_route_server(RouteServerId=route_server_id, VpcId=vpc_id)
    _poll_until(
        lambda: _association_state(ec2, route_server_id, vpc_id),
        lambda state: state is None,
        timeout_s=120,
        interval_s=5,
    )
    ec2.associate_route_server(RouteServerId=route_server_id, VpcId=other_vpc_id)
    ctx.on_cleanup(
        lambda: _disassociate_and_wait(ctx, route_server_id, other_vpc_id)
    )
    restored_state = _poll_until(
        lambda: _association_state(ec2, route_server_id, other_vpc_id),
        lambda state: state == "associated",
        timeout_s=120,
        interval_s=5,
    )
    assert restored_state == "associated", (
        f"expected {route_server_id} to associate with {other_vpc_id} after "
        f"disassociating {vpc_id}, got {restored_state!r}"
    )


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _association_state(ec2, route_server_id, vpc_id):
    from botocore.exceptions import ClientError

    try:
        associations = ec2.get_route_server_associations(RouteServerId=route_server_id)[
            "RouteServerAssociations"
        ]
    except ClientError as err:
        # A route server with no association answers InvalidRouteServerId.NotAssociated,
        # not an empty list.
        if err.response["Error"]["Code"] == "InvalidRouteServerId.NotAssociated":
            return None
        raise
    for assoc in associations:
        if assoc["VpcId"] == vpc_id:
            return assoc["State"]
    return None


def _disassociate_and_wait(ctx, route_server_id, vpc_id) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.disassociate_route_server(RouteServerId=route_server_id, VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidRouteServerId.NotAssociated",
            "InvalidVpcID.NotFound",
        ):
            raise
        return

    def _state():
        return _association_state(ec2, route_server_id, vpc_id)

    _poll_until(_state, lambda s: s in (None, "disassociated"), timeout_s=120, interval_s=5)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
