"""create-network-acl-entry."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-network-acl-entry"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_TAGS = [{"Key": "sim2real", "Value": "1"}]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNetworkAclEntry adds ingress rule 100 (10.0.0.0/24, allow, port 80) as one entry, and a second entry
    with the same number and direction is refused with NetworkAclEntryAlreadyExists "The network acl entry
    identified by 100 already exists." and leaves the first unchanged.
    """
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.72.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": _TAGS}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    acl_id = ec2.create_network_acl(
        VpcId=vpc_id, TagSpecifications=[{"ResourceType": "network-acl", "Tags": _TAGS}]
    )["NetworkAcl"]["NetworkAclId"]
    ctx.on_cleanup(lambda: ec2.delete_network_acl(NetworkAclId=acl_id))

    # CreateNetworkAclEntry's real response body carries nothing beyond ResponseMetadata (no
    # "Return" field, unlike some other Create* calls) -- the effect is verified below via
    # DescribeNetworkAcls.
    ec2.create_network_acl_entry(
        NetworkAclId=acl_id,
        RuleNumber=100,
        Protocol="6",
        RuleAction="allow",
        Egress=False,
        CidrBlock="10.0.0.0/24",
        PortRange={"From": 80, "To": 80},
    )

    entries = ec2.describe_network_acls(NetworkAclIds=[acl_id])["NetworkAcls"][0]["Entries"]
    matches = [e for e in entries if e["RuleNumber"] == 100 and e["Egress"] is False]
    assert len(matches) == 1, f"expected exactly one rule 100 ingress entry, got {matches!r}"
    entry = matches[0]
    assert entry["CidrBlock"] == "10.0.0.0/24", f"expected CidrBlock 10.0.0.0/24, got {entry['CidrBlock']!r}"
    assert entry["RuleAction"] == "allow", f"expected RuleAction allow, got {entry['RuleAction']!r}"
    assert entry["PortRange"] == {"From": 80, "To": 80}, f"expected PortRange 80-80, got {entry['PortRange']!r}"

    code, message = _client_error(
        lambda: ec2.create_network_acl_entry(
            NetworkAclId=acl_id,
            RuleNumber=100,
            Protocol="6",
            RuleAction="deny",
            Egress=False,
            CidrBlock="192.168.0.0/24",
            PortRange={"From": 443, "To": 443},
        )
    )
    assert code == "NetworkAclEntryAlreadyExists", f"expected NetworkAclEntryAlreadyExists, got {code!r}"
    expected_message = "The network acl entry identified by 100 already exists."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    unchanged = ec2.describe_network_acls(NetworkAclIds=[acl_id])["NetworkAcls"][0]["Entries"]
    matches_after = [e for e in unchanged if e["RuleNumber"] == 100 and e["Egress"] is False]
    assert matches_after == matches, "the rejected duplicate entry must not have mutated the existing rule"


def _client_error(fn):
    """Call *fn*; return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
