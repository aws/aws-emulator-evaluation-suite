"""op-contract-describe-vpcs."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-vpcs"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeVpcs returns a created VPC with its CIDR block once available, and an unknown VPC ID fails
    with InvalidVpcID.NotFound and its exact message."""
    ec2 = ctx.client("ec2")

    cidr = "10.204.0.0/16"
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=_tag_spec(ctx, "vpc", ctx.unique_name("sim2real-dvpc-")),
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    described = _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0],
        lambda v: v["State"] == "available",
        timeout_s=30.0,
    )
    assert described["CidrBlock"] == cidr, f"expected CidrBlock {cidr!r}, got {described['CidrBlock']!r}"
    assert described["VpcId"] == vpc_id, f"expected VpcId {vpc_id!r}, got {described['VpcId']!r}"

    code, message = _error(lambda: ec2.describe_vpcs(VpcIds=["vpc-00000000000000000"]))
    assert code == "InvalidVpcID.NotFound", f"expected InvalidVpcID.NotFound, got {code!r}"
    assert message == "The vpc ID 'vpc-00000000000000000' does not exist", message


def _tag_spec(ctx, resource_type: str, name: str):
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
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
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
