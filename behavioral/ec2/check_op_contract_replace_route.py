"""op-contract-replace-route."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-replace-route"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ReplaceRoute swaps a route's target for the same destination CIDR
    (success contract), and rejects replacing a CIDR with no existing route."""
    ec2 = ctx.client("ec2")

    # Reuse the run network's VPC/subnet when available; otherwise create them (retrying VpcLimitExceeded).
    vpc_id = _get_default_vpc(ec2, ctx=ctx)
    if vpc_id is None:
        vpc_id = _poll_until_success(
            lambda: ec2.create_vpc(CidrBlock="10.77.0.0/16",
                                    TagSpecifications=_tags("vpc", ctx.unique_name("sim2real-rr-")))["Vpc"]["VpcId"],
            retryable_codes={"VpcLimitExceeded"}, timeout_s=120, interval_s=10)
        ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    subnet_id = _get_any_subnet(ec2, vpc_id, ctx=ctx)
    if subnet_id is None:
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock="10.77.1.0/24",
            TagSpecifications=_tags("subnet", ctx.unique_name("sim2real-rr-")),
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    eni1 = ec2.create_network_interface(
        SubnetId=subnet_id, TagSpecifications=_tags("network-interface", ctx.unique_name("sim2real-rr-1-")),
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni1))

    eni2 = ec2.create_network_interface(
        SubnetId=subnet_id, TagSpecifications=_tags("network-interface", ctx.unique_name("sim2real-rr-2-")),
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni2))

    rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=_tags("route-table", ctx.unique_name("sim2real-rr-")),
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=rt_id))

    dest_cidr = "10.99.0.0/24"
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock=dest_cidr, NetworkInterfaceId=eni1)

    ec2.replace_route(RouteTableId=rt_id, DestinationCidrBlock=dest_cidr, NetworkInterfaceId=eni2)

    routes = ec2.describe_route_tables(RouteTableIds=[rt_id])["RouteTables"][0]["Routes"]
    matches = [r for r in routes if r.get("DestinationCidrBlock") == dest_cidr]
    assert len(matches) == 1, f"expected exactly one route for {dest_cidr}"
    assert matches[0]["NetworkInterfaceId"] == eni2, f"target was not replaced: {matches[0]}"

    # On real AWS, ReplaceRoute against a destination CIDR that has no
    # existing route in the table is rejected as InvalidParameterValue (the
    # "InvalidRoute.NotFound" code documented for some SDKs is not what the
    # service actually returns for this operation).
    code, message = _error(lambda: ec2.replace_route(
        RouteTableId=rt_id, DestinationCidrBlock="10.55.0.0/24", NetworkInterfaceId=eni1))
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    assert message == (
        "There is no route defined for '10.55.0.0/24' in the route table. Use CreateRoute instead."
    ), f"unexpected InvalidParameterValue message {message!r}"


def _tags(resource_type: str, name: str) -> list[dict]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _get_default_vpc(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(VpcIds=[ctx.network().vpc_id])["Vpcs"]
    defaults = [v for v in vpcs if v.get("IsDefault")]
    return defaults[0]["VpcId"] if defaults else None


def _get_any_subnet(ec2, vpc_id, *, ctx):
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    available = [s for s in subnets if s.get("State") == "available"]
    return available[0]["SubnetId"] if available else None


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _poll_until_success(fn, retryable_codes, timeout_s=120.0, interval_s=5.0):
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in retryable_codes:
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
