"""op-contract-describe-vpc-attribute."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-vpc-attribute"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeVpcAttribute reports the real default DNS attributes, rejects a bogus VpcId, and
    tracks the VpcId's lifecycle: the same call that just succeeded 404s once the VPC is deleted."""
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.123.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Vpc"]["VpcId"]

    def _cleanup():
        try:
            ec2.delete_vpc(VpcId=vpc_id)
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidVpcID.NotFound":
                raise

    ctx.on_cleanup(_cleanup)

    dns_support = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsSupport")
    assert dns_support["VpcId"] == vpc_id, f"expected VpcId {vpc_id}, got {dns_support['VpcId']}"
    assert dns_support["EnableDnsSupport"]["Value"] is True, (
        f"expected enableDnsSupport True on a fresh VPC, got {dns_support['EnableDnsSupport']}"
    )

    dns_hostnames = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsHostnames")
    assert dns_hostnames["VpcId"] == vpc_id, f"expected VpcId {vpc_id}, got {dns_hostnames['VpcId']}"
    # newly-created non-default VPCs do not enable DNS hostnames by default
    assert dns_hostnames["EnableDnsHostnames"]["Value"] is False, (
        f"expected enableDnsHostnames False on a fresh VPC, got {dns_hostnames['EnableDnsHostnames']}"
    )

    code, message = _client_error(
        lambda: ec2.describe_vpc_attribute(VpcId="vpc-0123456789abcdef0", Attribute="enableDnsSupport")
    )
    assert code == "InvalidVpcID.NotFound", f"expected InvalidVpcID.NotFound, got {code}"
    expected_message = "The vpc ID 'vpc-0123456789abcdef0' does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The VpcId lifecycle, not just a fabricated-id rejection: the identical call that succeeded
    # above must itself 404 once the id it named is gone.
    ec2.delete_vpc(VpcId=vpc_id)
    code_after_delete, code_after_delete_message = _client_error(
        lambda: ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsSupport")
    )
    assert code_after_delete == "InvalidVpcID.NotFound", (
        f"expected InvalidVpcID.NotFound for a deleted vpc_id, got {code_after_delete}"
    )
    expected_message = f"The vpc ID '{vpc_id}' does not exist"
    assert code_after_delete_message == expected_message, f"expected message {expected_message!r}, got {code_after_delete_message!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING an id real AWS rejects is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
