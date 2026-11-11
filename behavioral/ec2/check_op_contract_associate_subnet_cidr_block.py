"""op-contract-associateSubnetCidrBlock."""
from __future__ import annotations

import ipaddress
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-associateSubnetCidrBlock"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateSubnetCidrBlock adds an IPv6 /64 to a subnet; a nonexistent subnet is rejected."""
    ec2 = ctx.client("ec2")

    vpc = ec2.create_vpc(
        CidrBlock="10.193.0.0/16", AmazonProvidedIpv6CidrBlock=True,
        TagSpecifications=[_tag_spec("vpc", ctx.unique_name("sim2real-ascbvpc-"))],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc))

    ipv6_vpc_cidr = _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc])["Vpcs"][0].get("Ipv6CidrBlockAssociationSet", []),
        lambda assocs: bool(assocs) and assocs[0]["Ipv6CidrBlockState"]["State"] == "associated",
        timeout_s=60,
        interval_s=2,
    )[0]["Ipv6CidrBlock"]

    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet = ec2.create_subnet(
        VpcId=vpc, CidrBlock="10.193.1.0/24", AvailabilityZone=az,
        TagSpecifications=[_tag_spec("subnet", ctx.unique_name("sim2real-ascbsubnet-"))],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet))

    subnet_ipv6_cidr = str(next(ipaddress.ip_network(ipv6_vpc_cidr).subnets(new_prefix=64)))

    # error boundary: subnet does not exist
    code, code_message = _error_code(
        lambda: ec2.associate_subnet_cidr_block(SubnetId="subnet-00000000000000000", Ipv6CidrBlock=subnet_ipv6_cidr)
    )
    assert code == "InvalidSubnetID.NotFound", f"expected InvalidSubnetID.NotFound, got {code}"
    expected_code_message = "The subnet ID 'subnet-00000000000000000' does not exist"
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"

    # success path
    resp = ec2.associate_subnet_cidr_block(SubnetId=subnet, Ipv6CidrBlock=subnet_ipv6_cidr)
    assoc_id = resp["Ipv6CidrBlockAssociation"]["AssociationId"]
    initial_state = resp["Ipv6CidrBlockAssociation"]["Ipv6CidrBlockState"]["State"]
    assert initial_state in ("associating", "associated"), (
        f"expected associating/associated immediately after associate, got {initial_state}"
    )

    def cleanup_assoc():
        try:
            ec2.disassociate_subnet_cidr_block(AssociationId=assoc_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidSubnetCidrBlockAssociationID.NotFound":
                raise

    ctx.on_cleanup(cleanup_assoc)

    final = _poll_until(
        lambda: ec2.describe_subnets(SubnetIds=[subnet])["Subnets"][0]["Ipv6CidrBlockAssociationSet"],
        lambda assocs: any(a["AssociationId"] == assoc_id and a["Ipv6CidrBlockState"]["State"] == "associated" for a in assocs),
        timeout_s=60,
        interval_s=2,
    )
    match = [a for a in final if a["AssociationId"] == assoc_id][0]
    assert match["Ipv6CidrBlock"] == subnet_ipv6_cidr, (
        f"expected {subnet_ipv6_cidr}, got {match['Ipv6CidrBlock']}"
    )
    assert match["Ipv6CidrBlockState"]["State"] == "associated", (
        f"expected associated, got {match['Ipv6CidrBlockState']['State']}"
    )


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error")
        if not err:
            raise
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
