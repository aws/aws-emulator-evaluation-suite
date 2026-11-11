"""op-contract-delete-network-acl."""
from __future__ import annotations


from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-network-acl"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteNetworkAcl removes an unassociated custom NACL; deleting a NACL that is
    still associated with a subnet is rejected with DependencyViolation, and the same
    delete call succeeds once the association is lifted."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-nacl-")

    vpc_id = ec2.create_vpc(CidrBlock="10.82.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_error(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.82.1.0/24", TagSpecifications=[_tag_spec("subnet", name)]
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_error(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    # Capture the subnet's original (default) network ACL association so it can be restored.
    assoc = ec2.describe_network_acls(Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}])[
        "NetworkAcls"
    ][0]
    default_acl_id = assoc["NetworkAclId"]
    association_id = next(a["NetworkAclAssociationId"] for a in assoc["Associations"] if a["SubnetId"] == subnet_id)

    # Success path: an unassociated custom NACL can be deleted outright.
    acl_a = ec2.create_network_acl(VpcId=vpc_id, TagSpecifications=[_tag_spec("network-acl", name + "-a")])[
        "NetworkAcl"
    ]["NetworkAclId"]
    ec2.delete_network_acl(NetworkAclId=acl_a)
    gone = _error(lambda: ec2.describe_network_acls(NetworkAclIds=[acl_a]))
    assert gone == (
        "InvalidNetworkAclID.NotFound",
        f"The networkAcl ID '{acl_a}' does not exist",
    ), f"deleted ACL still resolvable: {gone}"

    # Error boundary: a NACL associated with a live subnet cannot be deleted.
    acl_b = ec2.create_network_acl(VpcId=vpc_id, TagSpecifications=[_tag_spec("network-acl", name + "-b")])[
        "NetworkAcl"
    ]["NetworkAclId"]

    new_assoc = ec2.replace_network_acl_association(AssociationId=association_id, NetworkAclId=acl_b)
    new_association_id = new_assoc["NewAssociationId"]

    def _revert_and_delete_acl_b():
        _cleanup_ignore_error(
            lambda: ec2.replace_network_acl_association(AssociationId=new_association_id, NetworkAclId=default_acl_id)
        )
        _cleanup_ignore_error(lambda: ec2.delete_network_acl(NetworkAclId=acl_b))

    ctx.on_cleanup(_revert_and_delete_acl_b)

    err = _error(lambda: ec2.delete_network_acl(NetworkAclId=acl_b))
    assert err == (
        "DependencyViolation",
        f"The networkAcl '{acl_b}' has dependencies and cannot be deleted.",
    ), f"unexpected error deleting an associated NACL: {err}"

    # Effect-absent: the rejected delete must not have taken the NACL away.
    still_there = ec2.describe_network_acls(NetworkAclIds=[acl_b])["NetworkAcls"][0]["NetworkAclId"]
    assert still_there == acl_b, f"NACL vanished despite DependencyViolation: {still_there!r}"

    # Restore: lift the association that caused the rejection.
    ec2.replace_network_acl_association(AssociationId=new_association_id, NetworkAclId=default_acl_id)

    # The identical delete call now succeeds once the dependency is gone.
    ec2.delete_network_acl(NetworkAclId=acl_b)
    gone_b = _error(lambda: ec2.describe_network_acls(NetworkAclIds=[acl_b]))
    assert gone_b == (
        "InvalidNetworkAclID.NotFound",
        f"The networkAcl ID '{acl_b}' does not exist",
    ), f"restored-then-deleted ACL still resolvable: {gone_b}"


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
            "InvalidAssociationID.NotFound",
            "InvalidNetworkAclID.NotFound",
            "InvalidSubnetID.NotFound",
            "InvalidVpcID.NotFound",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
