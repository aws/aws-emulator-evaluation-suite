"""route-server-delete-blocked-by-association-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "route-server-delete-blocked-by-association-rejected"
GROUP = "state-machine"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRouteServer is rejected while the route server still has a live
    VPC association; it succeeds once that association is removed
    (positive control in the same file)."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-rsdel-")

    vpc_id = ec2.create_vpc(CidrBlock="10.218.0.0/16", TagSpecifications=_tag_spec("vpc", name))[
        "Vpc"
    ]["VpcId"]
    ctx.on_cleanup(lambda: _ignore_error(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    rs_id = ec2.create_route_server(
        AmazonSideAsn=64512, TagSpecifications=_tag_spec("route-server", name)
    )["RouteServer"]["RouteServerId"]
    ctx.on_cleanup(lambda: _ignore_error(lambda: ec2.delete_route_server(RouteServerId=rs_id)))

    _poll_until(
        lambda: ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"][0]["State"],
        lambda s: s == "available",
        timeout_s=120,
        interval_s=3,
    )

    ec2.associate_route_server(RouteServerId=rs_id, VpcId=vpc_id)
    ctx.on_cleanup(
        lambda: _ignore_error(lambda: ec2.disassociate_route_server(RouteServerId=rs_id, VpcId=vpc_id))
    )

    def _assoc_state():
        try:
            assocs = ec2.get_route_server_associations(RouteServerId=rs_id)["RouteServerAssociations"]
        except Exception as exc:
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError) and exc.response["Error"]["Code"] == "InvalidRouteServerId.NotAssociated":
                return None
            raise
        for a in assocs:
            if a["VpcId"] == vpc_id:
                return a["State"]
        return None

    _poll_until(_assoc_state, lambda s: s == "associated", timeout_s=120, interval_s=3)

    # ---- Negative: delete is rejected while the association is live ----
    code, message = _error(lambda: ec2.delete_route_server(RouteServerId=rs_id))
    assert code == "IncorrectState", f"unexpected error code for delete-with-live-association: {code!r}"
    expected_message = f"Route Server has non-deleted association with VPC: {vpc_id}."
    assert message == expected_message, (
        f"unexpected message for delete-with-live-association: expected {expected_message!r}, got {message!r}"
    )

    # The route server is unaffected: still present, still 'available'.
    still_there = ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"]
    assert len(still_there) == 1
    assert still_there[0]["State"] == "available"

    # ---- Positive control: remove the dependency, then delete succeeds ----
    ec2.disassociate_route_server(RouteServerId=rs_id, VpcId=vpc_id)
    _poll_until(
        lambda: _assoc_state(), lambda s: s is None or s == "disassociating", timeout_s=120, interval_s=3
    )

    def _assoc_gone():
        return _assoc_state() is None

    _poll_until(_assoc_gone, lambda ok: ok, timeout_s=120, interval_s=3)

    ec2.delete_route_server(RouteServerId=rs_id)

    def _rs_terminal() -> bool:
        # Once the dependency is gone, delete succeeds and the route server
        # eventually stops being an 'available' resource (it 404s, or its
        # describe reflects a terminal 'deleted' state).
        from botocore.exceptions import ClientError

        try:
            rss = ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"]
        except ClientError:
            return True
        return bool(rss) and rss[0]["State"] == "deleted"

    _poll_until(_rs_terminal, lambda ok: ok, timeout_s=180, interval_s=5)


def _tag_spec(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _ignore_error(fn: Callable[[], Any]) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidRouteServerId.NotAssociated",
            "InvalidRouteServerId.NotFound",
            "InvalidVpcID.NotFound",
        ):
            raise


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
