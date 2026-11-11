"""op-contract-modify-vpc-attribute."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-modify-vpc-attribute"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVpcAttribute toggles enableDnsSupport and it is reflected by DescribeVpcAttribute; bad id -> NotFound."""
    ec2 = ctx.client("ec2")

    # The check toggles an attribute, so it owns its VPC: the run's shared network must not change.
    vpc_id = ec2.create_vpc(
        CidrBlock="10.66.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    original = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsSupport")["EnableDnsSupport"][
        "Value"
    ]
    ctx.on_cleanup(lambda: ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": original}))

    flipped = not original
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": flipped})

    after = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsSupport")
    assert after["EnableDnsSupport"]["Value"] == flipped, after

    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": original})
    restored = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsSupport")
    assert restored["EnableDnsSupport"]["Value"] == original, restored

    code, message = _client_error(
        lambda: ec2.modify_vpc_attribute(VpcId="vpc-00000000000000000", EnableDnsSupport={"Value": True})
    )
    assert code == "InvalidVpcID.NotFound", f"unexpected error code: {code}"
    expected_message = "The vpc ID 'vpc-00000000000000000' does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Call fn() and return its error (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
