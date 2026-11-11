"""op-contract-delete-network-acl-entry."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-network-acl-entry"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteNetworkAclEntry removes a single ingress/egress rule from a NACL;
    referencing an unknown network ACL ID is rejected with InvalidNetworkAclID.NotFound."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-naclentry-")

    vpc_id = ec2.create_vpc(CidrBlock="10.83.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_error(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    acl_id = ec2.create_network_acl(VpcId=vpc_id, TagSpecifications=[_tag_spec("network-acl", name)])[
        "NetworkAcl"
    ]["NetworkAclId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_error(lambda: ec2.delete_network_acl(NetworkAclId=acl_id)))

    ec2.create_network_acl_entry(
        NetworkAclId=acl_id,
        RuleNumber=100,
        Protocol="6",
        RuleAction="allow",
        Egress=False,
        CidrBlock="203.0.113.0/24",
        PortRange={"From": 443, "To": 443},
    )

    def _entries():
        return ec2.describe_network_acls(NetworkAclIds=[acl_id])["NetworkAcls"][0]["Entries"]

    before = [e for e in _entries() if e["RuleNumber"] == 100 and not e["Egress"]]
    assert len(before) == 1, f"entry not created: {_entries()}"

    ec2.delete_network_acl_entry(NetworkAclId=acl_id, RuleNumber=100, Egress=False)

    after = [e for e in _entries() if e["RuleNumber"] == 100 and not e["Egress"]]
    assert after == [], f"entry still present after delete: {after}"

    # Use a genuinely unassigned NACL id rather than a fabricated one: flipping a hex
    # character of a real id can still land on a value real AWS rejects up front as
    # InvalidNetworkAclId.Malformed, before it ever reaches the
    # existence check this negative is meant to probe. Create a real, correctly
    # formatted-for-this-account NACL and immediately delete it, so the id is
    # guaranteed well-formed and guaranteed not to exist.
    throwaway_acl_id = ec2.create_network_acl(
        VpcId=vpc_id, TagSpecifications=[_tag_spec("network-acl", name + "-gone")]
    )["NetworkAcl"]["NetworkAclId"]
    ec2.delete_network_acl(NetworkAclId=throwaway_acl_id)

    code, message = _error(
        lambda: ec2.delete_network_acl_entry(NetworkAclId=throwaway_acl_id, RuleNumber=100, Egress=False)
    )
    assert code == "InvalidNetworkAclID.NotFound", (
        f"unexpected error deleting an entry of an unknown NACL: {code}: {message}"
    )
    assert message == f"The networkAcl ID '{throwaway_acl_id}' does not exist", (
        f"unexpected error deleting an entry of an unknown NACL: {code}: {message}"
    )


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _error(fn):
    """Call fn() and return its ClientError (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _cleanup_ignore_error(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidNetworkAclID.NotFound",
            "InvalidVpcID.NotFound",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
