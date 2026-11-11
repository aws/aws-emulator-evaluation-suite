"""op-contract-replace-network-acl-association."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-replace-network-acl-association"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ReplaceNetworkAclAssociation moves a subnet's ACL association to a new
    NACL (success contract), and rejects an unknown association ID."""
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(CidrBlock="10.75.0.0/16",
                             TagSpecifications=_tags("vpc", ctx.unique_name("sim2real-rnaa-")))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    _poll_until(lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
                lambda s: s == "available", timeout_s=60, interval_s=2)

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.75.1.0/24",
        TagSpecifications=_tags("subnet", ctx.unique_name("sim2real-rnaa-")),
    )["Subnet"]["SubnetId"]

    new_acl_id = ec2.create_network_acl(
        VpcId=vpc_id, TagSpecifications=_tags("network-acl", ctx.unique_name("sim2real-rnaa-")),
    )["NetworkAcl"]["NetworkAclId"]
    ctx.on_cleanup(lambda: ec2.delete_network_acl(NetworkAclId=new_acl_id))
    # Registered after the NACL's cleanup so LIFO teardown deletes the subnet (dissolving
    # its association) before the NACL delete is attempted; otherwise the NACL is still
    # associated and delete_network_acl fails with DependencyViolation, leaking both it and
    # the VPC (which cannot be deleted while a custom NACL remains).
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    current = ec2.describe_network_acls(
        Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
    )["NetworkAcls"][0]
    old_acl_id = current["NetworkAclId"]
    assoc = next(a for a in current["Associations"] if a["SubnetId"] == subnet_id)
    old_assoc_id = assoc["NetworkAclAssociationId"]

    resp = ec2.replace_network_acl_association(AssociationId=old_assoc_id, NetworkAclId=new_acl_id)
    new_assoc_id = resp["NewAssociationId"]
    assert new_assoc_id and new_assoc_id != old_assoc_id

    refreshed = ec2.describe_network_acls(NetworkAclIds=[new_acl_id])["NetworkAcls"][0]
    matches = [a for a in refreshed["Associations"] if a["SubnetId"] == subnet_id]
    assert len(matches) == 1, "subnet is not associated with the new NACL"
    assert matches[0]["NetworkAclAssociationId"] == new_assoc_id

    old_refreshed = ec2.describe_network_acls(NetworkAclIds=[old_acl_id])["NetworkAcls"][0]
    stale = [a for a in old_refreshed["Associations"] if a["SubnetId"] == subnet_id]
    assert not stale, "subnet is still associated with the old NACL; association was duplicated, not moved"

    code, message = _error(lambda: ec2.replace_network_acl_association(
        AssociationId="aclassoc-00000000000000000", NetworkAclId=new_acl_id))
    assert code == "InvalidAssociationID.NotFound", f"expected InvalidAssociationID.NotFound, got {code}"
    assert message == "The association ID 'aclassoc-00000000000000000' does not exist", (
        f"unexpected InvalidAssociationID.NotFound message {message!r}")


def _tags(resource_type: str, name: str) -> list[dict]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
