"""create-network-acl."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-network-acl"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNetworkAcl in a VPC returns a non-default ACL of that VPC with a deny entry per direction, while an
    unknown VPC is refused with InvalidVpcID.NotFound "The vpc ID 'vpc-00000000000000000' does not exist".
    """
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.71.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    created = ec2.create_network_acl(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "network-acl", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["NetworkAcl"]
    acl_id = created["NetworkAclId"]
    ctx.on_cleanup(lambda: ec2.delete_network_acl(NetworkAclId=acl_id))

    acl = ec2.describe_network_acls(NetworkAclIds=[acl_id])["NetworkAcls"][0]
    assert acl["VpcId"] == vpc_id
    assert acl["IsDefault"] is False
    default_entries = [
        e for e in acl["Entries"] if e["RuleNumber"] == 32767 and e.get("CidrBlock") == "0.0.0.0/0"
    ]
    directions = {e["Egress"] for e in default_entries}
    assert directions == {True, False}, f"expected a default deny-all entry per direction, got {acl['Entries']!r}"
    assert all(e["RuleAction"] == "deny" for e in default_entries)

    code, message = _error(lambda: ec2.create_network_acl(VpcId="vpc-00000000000000000"))
    assert code == "InvalidVpcID.NotFound", f"expected InvalidVpcID.NotFound, got {code!r}"
    assert message == "The vpc ID 'vpc-00000000000000000' does not exist", message


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
