"""modify-vpc-attribute-conflicting-attrs-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "modify-vpc-attribute-conflicting-attrs-rejected"
GROUP = "overly-permissive"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyVpcAttribute rejects setting EnableDnsSupport and EnableDnsHostnames in the same call."""
    ec2 = ctx.client("ec2")

    # The check flips the VPC's DNS support, so it uses a VPC of its own, deleted in teardown.
    vpc_id = ec2.create_vpc(
        CidrBlock="10.209.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [
            {"Key": "Name", "Value": ctx.unique_name("sim2real-vpcattr-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc(ec2, vpc_id))
    _wait_vpc_available(ec2, vpc_id)

    original = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsSupport")["EnableDnsSupport"][
        "Value"
    ]

    # Positive control: a single-attribute ModifyVpcAttribute call on this same VPC must
    # succeed and take effect, proving the account, credentials and this VPC are otherwise
    # healthy for the operation. Without this, "rejects the conflicting combination" is
    # indistinguishable from "rejects every ModifyVpcAttribute call".
    flipped = not original
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": flipped})
    control = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsSupport")
    assert control["EnableDnsSupport"]["Value"] == flipped, (
        f"positive control failed: expected EnableDnsSupport={flipped}, got {control}"
    )
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": original})
    restored = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsSupport")
    assert restored["EnableDnsSupport"]["Value"] == original, (
        f"positive control restore failed: expected EnableDnsSupport={original}, got {restored}"
    )

    code, message = _error(
        lambda: ec2.modify_vpc_attribute(
            VpcId=vpc_id,
            EnableDnsSupport={"Value": not original},
            EnableDnsHostnames={"Value": True},
        )
    )
    assert code == "InvalidParameterCombination", f"unexpected error code: {code}"
    assert message.startswith("Fields for multiple attribute types specified: "), message
    assert set(message.split(": ", 1)[1].split(", ")) == {"enableDnsHostnames", "enableDnsSupport"}, message

    # The VPC's DNS support attribute must remain untouched by the rejected call.
    unchanged = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsSupport")
    assert unchanged["EnableDnsSupport"]["Value"] == original, (
        f"expected EnableDnsSupport unchanged at {original} after rejected call, got {unchanged}"
    )


def _wait_vpc_available(ec2, vpc_id, timeout_s=60.0):
    """A new VPC id can answer InvalidVpcID.NotFound briefly before it reads available."""
    import time

    from botocore.exceptions import ClientError

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


def _delete_vpc(ec2, vpc_id):
    """Teardown: delete the check's VPC; an already-deleted VPC is fine, anything else raises."""
    from botocore.exceptions import ClientError

    try:
        ec2.delete_vpc(VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
            raise


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
