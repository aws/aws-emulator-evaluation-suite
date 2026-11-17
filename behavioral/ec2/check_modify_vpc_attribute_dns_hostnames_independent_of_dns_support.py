"""modify-vpc-attribute-dns-hostnames-independent-of-dns-support."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-vpc-attribute-dns-hostnames-independent-of-dns-support"
GROUP = "vpc-subnet"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new VPC defaults EnableDnsSupport true and EnableDnsHostnames false; toggling either
    attribute with ModifyVpcAttribute leaves the other's DescribeVpcAttribute reading unchanged.
    """
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.77.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [
            {"Key": "Name", "Value": ctx.unique_name("sim2real-vpcdns-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))
    _wait_vpc_available(ec2, vpc_id)

    support = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsSupport")
    assert support["EnableDnsSupport"]["Value"] is True, (
        f"expected a freshly created VPC to default EnableDnsSupport True, got {support['EnableDnsSupport']!r}"
    )
    hostnames = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsHostnames")
    assert hostnames["EnableDnsHostnames"]["Value"] is False, (
        f"expected a freshly created VPC to default EnableDnsHostnames False, got {hostnames['EnableDnsHostnames']!r}"
    )

    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    hostnames_on = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsHostnames")
    assert hostnames_on["EnableDnsHostnames"]["Value"] is True, (
        f"expected EnableDnsHostnames True after enabling it, got {hostnames_on['EnableDnsHostnames']!r}"
    )
    support_unchanged_1 = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsSupport")
    assert support_unchanged_1["EnableDnsSupport"]["Value"] is True, (
        f"enabling EnableDnsHostnames must not change EnableDnsSupport, got {support_unchanged_1['EnableDnsSupport']!r}"
    )

    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": False})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": False})
    hostnames_after_support_off = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsHostnames")
    assert hostnames_after_support_off["EnableDnsHostnames"]["Value"] is False, (
        f"expected EnableDnsHostnames to read False after separately disabling both attributes, "
        f"got {hostnames_after_support_off['EnableDnsHostnames']!r}"
    )
    support_after_both_off = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsSupport")
    assert support_after_both_off["EnableDnsSupport"]["Value"] is False, (
        f"expected EnableDnsSupport False after disabling it, got {support_after_both_off['EnableDnsSupport']!r}"
    )

    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    support_restored = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsSupport")
    assert support_restored["EnableDnsSupport"]["Value"] is True, (
        f"expected EnableDnsSupport True after restoring it, got {support_restored['EnableDnsSupport']!r}"
    )
    hostnames_after_restore = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsHostnames")
    assert hostnames_after_restore["EnableDnsHostnames"]["Value"] is False, (
        f"restoring EnableDnsSupport must leave EnableDnsHostnames at its own last value False, "
        f"got {hostnames_after_restore['EnableDnsHostnames']!r}"
    )


def _wait_vpc_available(ec2, vpc_id, timeout_s: float = 60.0) -> None:
    """A new VPC id can answer InvalidVpcID.NotFound briefly before it reads available."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"] == "available":
                return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
                raise
        time.sleep(2.0)
    raise AssertionError(f"VPC {vpc_id} did not become available within {timeout_s}s")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` codes pass."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
