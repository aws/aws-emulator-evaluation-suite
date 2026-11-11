"""op-contract-describe-dhcp-options."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-dhcp-options"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDhcpOptions returns a created DHCP options set with its domain name servers and Name tag;
    both a well-formed unknown ID and a string not shaped like a dopt ID fail with
    InvalidDhcpOptionID.NotFound and the exact message naming the ID."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-dopt-")

    created = ec2.create_dhcp_options(
        DhcpConfigurations=[
            {"Key": "domain-name-servers", "Values": ["10.0.0.2", "10.0.0.3"]}
        ],
        TagSpecifications=[
            {"ResourceType": "dhcp-options", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["DhcpOptions"]
    dopt_id = created["DhcpOptionsId"]
    ctx.on_cleanup(lambda: ec2.delete_dhcp_options(DhcpOptionsId=dopt_id))

    described = ec2.describe_dhcp_options(DhcpOptionsIds=[dopt_id])["DhcpOptions"][0]
    servers = next(
        c["Values"] for c in described["DhcpConfigurations"] if c["Key"] == "domain-name-servers"
    )
    assert set(v["Value"] for v in servers) == {"10.0.0.2", "10.0.0.3"}
    assert {"Key": "Name", "Value": name} in described.get("Tags", [])

    # Rejection boundary #1: a well-formed but nonexistent ID. This code spells "DhcpOptionID" in the
    # singular, not "DhcpOptionsID".
    not_found_code, not_found_message = _error(
        lambda: ec2.describe_dhcp_options(DhcpOptionsIds=["dopt-" + "0" * 17])
    )
    assert not_found_code == "InvalidDhcpOptionID.NotFound", (
        f"expected InvalidDhcpOptionID.NotFound, got {not_found_code}"
    )
    assert not_found_message == "The dhcpOption ID 'dopt-00000000000000000' does not exist", not_found_message

    # Rejection boundary #2: an ID not shaped like a dopt ID. DescribeDhcpOptions has no separate shape
    # validation, so any unresolvable ID fails with the same InvalidDhcpOptionID.NotFound.
    not_found_code_2, not_found_message_2 = _error(
        lambda: ec2.describe_dhcp_options(DhcpOptionsIds=["not-a-valid-dhcp-options-id"])
    )
    assert not_found_code_2 == "InvalidDhcpOptionID.NotFound", (
        f"expected InvalidDhcpOptionID.NotFound, got {not_found_code_2}"
    )
    assert not_found_message_2 == "The dhcpOption ID 'not-a-valid-dhcp-options-id' does not exist", not_found_message_2


def _error(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises, because an emulator
    ACCEPTING an id real AWS rejects is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
