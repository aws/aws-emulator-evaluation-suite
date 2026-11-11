"""op-contract-get-vpc-resources-blocking-encryption-enforcement."""
from __future__ import annotations

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "op-contract-get-vpc-resources-blocking-encryption-enforcement"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetVpcResourcesBlockingEncryptionEnforcement returns a NonCompliantResources list for a real VPC;
    an unknown VPC id fails with InvalidVpcID.NotFound and its exact message."""
    ec2 = ctx.client("ec2")

    vpc_id = ctx.network().vpc_id

    resp = ec2.get_vpc_resources_blocking_encryption_enforcement(VpcId=vpc_id)
    non_compliant = resp.get("NonCompliantResources", [])
    assert isinstance(non_compliant, list), (
        f"expected NonCompliantResources (when present) to be a list, got {resp!r}"
    )

    code, message = _error(
        lambda: ec2.get_vpc_resources_blocking_encryption_enforcement(VpcId="vpc-00000000")
    )
    assert code == "InvalidVpcID.NotFound", f"expected InvalidVpcID.NotFound, got {code!r}"
    assert message == "The vpc ID 'vpc-00000000' does not exist", message


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected InvalidVpcID.NotFound but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
