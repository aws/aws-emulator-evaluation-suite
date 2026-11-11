"""op-contract-associate-dhcp-options."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-associate-dhcp-options"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateDhcpOptions swaps a VPC's DHCP options set; a bogus options-set id is rejected."""
    ec2 = ctx.client("ec2")
    # A VPC of its own: the default VPC's DHCP options are account baseline and never changed.
    vpc_id = _own_vpc(ctx, ec2)

    original = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["DhcpOptionsId"]

    dhcp_opts_id = ec2.create_dhcp_options(
        DhcpConfigurations=[{"Key": "domain-name-servers", "Values": ["AmazonProvidedDNS"]}],
        TagSpecifications=[
            {"ResourceType": "dhcp-options", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-dhcp-")}]}
        ],
    )["DhcpOptions"]["DhcpOptionsId"]
    ctx.on_cleanup(lambda: _drop_dhcp_options(ec2, dhcp_opts_id, vpc_id))
    assert dhcp_opts_id != original, f"newly created options set {dhcp_opts_id} collided with the VPC's existing {original}"

    ec2.associate_dhcp_options(DhcpOptionsId=dhcp_opts_id, VpcId=vpc_id)

    described = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    assert described["DhcpOptionsId"] == dhcp_opts_id, f"VPC still shows {described['DhcpOptionsId']}"

    # Restore the VPC's original DHCP options set before the new one is deleted in cleanup.
    # NB: the literal sentinel "default" associates the VPC with the *account's* default
    # DHCP options set, which is not necessarily the set the VPC had before this check ran
    # (a real account's default VPC can already carry a non-default, custom options set) --
    # so we must restore by the actual original id we captured, not the "default" sentinel.
    ec2.associate_dhcp_options(DhcpOptionsId=original, VpcId=vpc_id)
    restored = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["DhcpOptionsId"]
    assert restored == original, f"expected restore to {original}, got {restored}"

    # A bogus options-set id is rejected. Note that even an id built by substituting random
    # hex characters into a real id's suffix (same length/charset as a genuine dopt-* id) is
    # *not* guaranteed to land on a not-found id: EC2 resource ids of this length are not
    # purely random -- their bit layout encodes internal structure, so a random suffix
    # commonly fails EC2's own id-shape validity check before a lookup is even attempted.
    # EC2 rejects an id that fails its id-shape check with
    # "InvalidDhcpOptionsId.Malformed" (lowercase "Id", not "NotFound").
    fake_dhcp_opts_id = _random_sibling_id(dhcp_opts_id)
    code, message = _client_error(
        lambda: ec2.associate_dhcp_options(DhcpOptionsId=fake_dhcp_opts_id, VpcId=vpc_id)
    )
    assert code == "InvalidDhcpOptionsId.Malformed", f"unexpected error code: {code}"
    expected = f'Invalid id: "{fake_dhcp_opts_id}"'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The rejected association must not have taken partial effect: an independent read still
    # shows the VPC on the options set it held before the rejected call.
    unchanged = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["DhcpOptionsId"]
    assert unchanged == original, f"rejected AssociateDhcpOptions still changed VPC to {unchanged}"


def _own_vpc(ctx, ec2) -> str:
    vpc_id = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-dhcp-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return vpc_id


def _drop_dhcp_options(ec2, dhcp_opts_id, vpc_id):
    """Free the set from this check's VPC (a no-op once restored), then delete it."""
    from botocore.exceptions import ClientError

    ec2.associate_dhcp_options(DhcpOptionsId="default", VpcId=vpc_id)
    try:
        ec2.delete_dhcp_options(DhcpOptionsId=dhcp_opts_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidDhcpOptionID.NotFound", "InvalidDhcpOptionsID.NotFound"):
            raise


def _random_sibling_id(real_id: str) -> str:
    import secrets

    prefix, _, suffix = real_id.partition("-")
    alphabet = "0123456789abcdef"
    fake_suffix = "".join(secrets.choice(alphabet) for _ in suffix)
    return f"{prefix}-{fake_suffix}"


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because a target
    ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
