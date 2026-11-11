"""op-contract-delete-route-table-dependency-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-route-table-dependency-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRouteTable succeeds on an unassociated table; fails DependencyViolation while
    the table still has an explicit subnet association (must disassociate first)."""
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(CidrBlock="10.93.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    _tag(ec2, vpc_id, ctx.unique_name("sim2real-behav-rtb-vpc-"))

    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.93.1.0/24")["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    free_rtb_id = ec2.create_route_table(VpcId=vpc_id)["RouteTable"]["RouteTableId"]
    resp = ec2.delete_route_table(RouteTableId=free_rtb_id)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200 deleting an unassociated route table, got {resp['ResponseMetadata']!r}"
    )
    code, msg = _client_error(lambda: ec2.describe_route_tables(RouteTableIds=[free_rtb_id]))
    assert code == "InvalidRouteTableID.NotFound", f"expected NotFound, got {code!r}"
    expected_msg = f"The routeTable ID '{free_rtb_id}' does not exist"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Error boundary: a route table with an explicit subnet association cannot be deleted.
    assoc_rtb_id = ec2.create_route_table(VpcId=vpc_id)["RouteTable"]["RouteTableId"]
    _tag(ec2, assoc_rtb_id, ctx.unique_name("sim2real-behav-rtb-assoc-"))
    assoc_id = ec2.associate_route_table(RouteTableId=assoc_rtb_id, SubnetId=subnet_id)[
        "AssociationId"
    ]

    def _cleanup_assoc_rtb() -> None:
        try:
            ec2.disassociate_route_table(AssociationId=assoc_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidAssociationID.NotFound":
                raise
        try:
            ec2.delete_route_table(RouteTableId=assoc_rtb_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidRouteTableID.NotFound":
                raise

    ctx.on_cleanup(_cleanup_assoc_rtb)

    code, msg = _client_error(lambda: ec2.delete_route_table(RouteTableId=assoc_rtb_id))
    assert code == "DependencyViolation", f"expected DependencyViolation, got {code!r}"
    expected_msg = f"The routeTable '{assoc_rtb_id}' has dependencies and cannot be deleted."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    still_there = ec2.describe_route_tables(RouteTableIds=[assoc_rtb_id])["RouteTables"]
    assert len(still_there) == 1 and still_there[0]["RouteTableId"] == assoc_rtb_id, (
        f"route table should still exist after a DependencyViolation, got {still_there!r}"
    )

    # Disassociation propagates asynchronously, so the delete is retried briefly.
    ec2.disassociate_route_table(AssociationId=assoc_id)
    _poll_until(
        lambda: _succeeds(lambda: ec2.delete_route_table(RouteTableId=assoc_rtb_id)),
        lambda ok: ok is True,
        timeout_s=30,
    )

    final_code, final_msg = _client_error(
        lambda: ec2.describe_route_tables(RouteTableIds=[assoc_rtb_id])
    )
    assert final_code == "InvalidRouteTableID.NotFound", (
        f"expected NotFound after the delete succeeded, got {final_code!r}"
    )
    expected_msg = f"The routeTable ID '{assoc_rtb_id}' does not exist"
    assert final_msg == expected_msg, f"expected message {expected_msg!r}, got {final_msg!r}"


def _tag(ec2: Any, resource_id: str, name: str) -> None:
    ec2.create_tags(Resources=[resource_id], Tags=[{"Key": "Name", "Value": name}])


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _succeeds(fn: Callable[[], Any]) -> bool:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError:
        return False
    return True


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
