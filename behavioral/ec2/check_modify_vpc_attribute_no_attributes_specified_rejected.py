"""modify-vpc-attribute-no-attributes-specified-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-vpc-attribute-no-attributes-specified-rejected"
GROUP = "overly-permissive"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyVpcAttribute with no attribute parameter is rejected and changes nothing."""
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.78.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [
            {"Key": "Name", "Value": ctx.unique_name("sim2real-vpcattrnone-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))
    _wait_vpc_available(ec2, vpc_id)

    original = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsSupport")[
        "EnableDnsSupport"
    ]["Value"]

    code, message = _error(lambda: ec2.modify_vpc_attribute(VpcId=vpc_id))
    assert code == "InvalidParameterCombination", f"unexpected error code: {code}"
    assert message == "No attributes specified.", f"unexpected error message: {message!r}"

    unchanged = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsSupport")
    assert unchanged["EnableDnsSupport"]["Value"] == original, (
        f"expected EnableDnsSupport unchanged at {original!r} after the rejected call, "
        f"got {unchanged['EnableDnsSupport']!r}"
    )

    # Positive control: the same VPC, the same operation, with exactly one attribute named,
    # must still succeed — proving the rejection is about the empty parameter set, not this VPC
    # or this call having gone generally bad.
    flipped = not original
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": flipped})
    control = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsSupport")
    assert control["EnableDnsSupport"]["Value"] == flipped, (
        f"positive control failed: expected EnableDnsSupport={flipped}, got {control['EnableDnsSupport']!r}"
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


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
