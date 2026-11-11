"""op-contract-createVpcEndpoint."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-createVpcEndpoint"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpcEndpoint creates a Gateway endpoint that DescribeVpcEndpoints shows available in the VPC
    with the route table attached; a nonexistent VpcId is rejected with InvalidVpcID.NotFound or an
    InvalidParameter message naming the VPC."""
    ec2 = ctx.client("ec2")
    region = ctx.region

    vpc_id = _create_vpc(ec2, "10.211.0.0/16", _tag_spec(ctx, "vpc", "vpce-create-vpc"))
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=_tag_spec(ctx, "route-table", "vpce-create-rt")
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=rt_id))

    resp = ec2.create_vpc_endpoint(
        VpcId=vpc_id,
        ServiceName=f"com.amazonaws.{region}.s3",
        VpcEndpointType="Gateway",
        RouteTableIds=[rt_id],
        TagSpecifications=_tag_spec(ctx, "vpc-endpoint", "vpce-create-ep"),
    )
    endpoint_id = resp["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=[endpoint_id]))

    # Independent read: the create call's own response is not proof the endpoint actually
    # persisted with these attributes -- describe it back through a different operation.
    described = _poll_until(
        lambda: ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0],
        lambda ep: ep["State"] == "available",
        timeout_s=60.0,
    )
    assert described["VpcId"] == vpc_id, f"expected VpcId {vpc_id!r}, got {described['VpcId']!r}"
    assert described["State"] == "available", (
        f"expected State 'available' on independent read, got {described['State']!r}"
    )
    assert rt_id in described.get("RouteTableIds", []), (
        f"expected route table {rt_id!r} bound on independent read, "
        f"got {described.get('RouteTableIds')!r}"
    )

    # Error boundary: a well-formed nonexistent VpcId, with RouteTableIds omitted because a route table
    # is validated before the VpcId. The VPC endpoints API answers either InvalidVpcID.NotFound or
    # InvalidParameter with the VPC named in the message; accept either, tied to the VpcId.
    code, message = _error_code_and_message(
        lambda: ec2.create_vpc_endpoint(
            VpcId="vpc-00000000000000000",
            ServiceName=f"com.amazonaws.{region}.s3",
            VpcEndpointType="Gateway",
        )
    )
    lowered_code = (code or "").lower()
    lowered_msg = (message or "").lower()
    is_notfound_code = "vpcid" in lowered_code and "notfound" in lowered_code
    is_generic_with_vpc_message = lowered_code == "invalidparameter" and "vpc" in lowered_msg
    assert is_notfound_code or is_generic_with_vpc_message, (
        f"expected a VpcId-not-found style rejection, got code={code!r} message={message!r}"
    )


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    return None, None


def _create_vpc(ec2, cidr_block, tag_specs):
    """Create a VPC and raise if the VPC quota is exhausted: a check never frees quota by deleting
    resources it does not own."""
    return ec2.create_vpc(CidrBlock=cidr_block, TagSpecifications=tag_specs)["Vpc"]["VpcId"]


def _tag_spec(ctx, resource_type: str, prefix: str) -> list:
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
        }
    ]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
