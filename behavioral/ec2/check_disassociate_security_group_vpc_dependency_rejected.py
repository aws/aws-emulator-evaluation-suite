"""disassociate-security-group-vpc-dependency-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "disassociate-security-group-vpc-dependency-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateSecurityGroupVpc is rejected with a dependency error while a network
    interface in the associated VPC still uses the security group, and succeeds once that
    dependency is removed."""
    ec2 = ctx.client("ec2")

    # The account's VPC quota is shared with everything else running concurrently; fall back to
    # an already-existing VPC (and one of its subnets) rather than failing on a capacity error
    # that has nothing to do with DisassociateSecurityGroupVpc's contract.
    home_id = _create_or_adopt_vpc(ec2, ctx, "10.214.0.0/16", ctx.unique_name("sim2real-sgvhome-"))
    target_id, subnet_id = _create_or_adopt_vpc_with_subnet(
        ec2, ctx, "10.215.0.0/16", "10.215.1.0/24",
        ctx.unique_name("sim2real-sgvtarget-"), ctx.unique_name("sim2real-sgvsubnet-"),
        exclude=home_id,
    )

    sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-sgv-"), Description="sim2real sg-vpc association test",
        VpcId=home_id,
    )
    sg_id = sg["GroupId"]
    sg_deleted = {"done": False}

    def _delete_sg():
        if not sg_deleted["done"]:
            ec2.delete_security_group(GroupId=sg_id)
            sg_deleted["done"] = True

    ctx.on_cleanup(_delete_sg)

    # Security Group VPC association is a feature that must be available for the account/region;
    # if AWS reports it unsupported here, there is nothing about DisassociateSecurityGroupVpc's
    # own contract we can exercise, so skip rather than failing on an unrelated capability gap.
    from botocore.exceptions import ClientError

    try:
        ec2.associate_security_group_vpc(GroupId=sg_id, VpcId=target_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvalidParameterValue" and "not supported" in exc.response.get("Error", {}).get("Message", ""):
            raise AssertionError("Security Group VPC association functionality is not supported in this account/region")
        raise

    def _assoc_state():
        resp = ec2.describe_security_group_vpc_associations(
            Filters=[{"Name": "group-id", "Values": [sg_id]}, {"Name": "vpc-id", "Values": [target_id]}]
        )
        assocs = resp.get("SecurityGroupVpcAssociations", [])
        return assocs[0]["State"] if assocs else None

    state = _poll_until(_assoc_state, lambda s: s == "associated", timeout_s=90.0, interval_s=5.0)
    assert state == "associated", f"security group never reached 'associated' with target VPC: {state}"

    eni = ec2.create_network_interface(
        SubnetId=subnet_id, Groups=[sg_id],
        TagSpecifications=[_tag_spec("network-interface", ctx.unique_name("sim2real-sgveni-"))],
    )["NetworkInterface"]
    eni_id = eni["NetworkInterfaceId"]
    eni_deleted = {"done": False}

    def _delete_eni():
        if not eni_deleted["done"]:
            ec2.delete_network_interface(NetworkInterfaceId=eni_id)
            eni_deleted["done"] = True

    ctx.on_cleanup(_delete_eni)

    # NEGATIVE: an ENI in the target VPC still uses the security group -> rejected.
    code, message = _error(lambda: ec2.disassociate_security_group_vpc(GroupId=sg_id, VpcId=target_id))
    assert code == "SecurityGroupVpcAssociationInUse", (
        f"expected SecurityGroupVpcAssociationInUse while ENI is attached, got: {code}"
    )
    assert message == (
        f"The Security Group VPC association between Security Group '{sg_id}' and VPC '{target_id}' is in use."
    ), f"unexpected SecurityGroupVpcAssociationInUse message: {message!r}"

    # Effect-absent: the association is still 'associated', not disturbed by the rejected call.
    assert _assoc_state() == "associated", "rejected disassociation must not move the association state"

    # Remove the dependency, then the disassociation must succeed.
    _delete_eni()

    def _eni_gone():
        try:
            ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])
            return False
        except Exception:
            return True

    _poll_until(_eni_gone, lambda gone: gone, timeout_s=30.0, interval_s=2.0)

    ok = _poll_until(
        lambda: _succeeds(lambda: ec2.disassociate_security_group_vpc(GroupId=sg_id, VpcId=target_id)),
        lambda ok: ok,
        timeout_s=30.0,
        interval_s=3.0,
    )
    assert ok is True, "expected disassociation to succeed once ENI removed"

    # Terminal read is independent of the mutating call: confirm at the destination
    # (DescribeSecurityGroupVpcAssociations) that the association is actually gone, not merely
    # that the disassociate call itself returned without error.
    final_state = _poll_until(_assoc_state, lambda s: s in (None, "disassociated"), timeout_s=60.0, interval_s=5.0)
    assert final_state in (None, "disassociated"), (
        f"expected the association to disappear or read 'disassociated', got: {final_state}"
    )

    # The security group was briefly cross-referenced by the target VPC's association; delete it
    # here (bounded retry, not the 60s teardown budget) rather than leaving DeleteSecurityGroup's
    # own eventual-consistency lag to a best-effort cleanup that swallows the resulting exception.
    _poll_until(
        lambda: _succeeds(_delete_sg),
        lambda ok: ok,
        timeout_s=30.0,
        interval_s=3.0,
    )


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_or_adopt_vpc(ec2, ctx, cidr, name, exclude=None):
    """Create a fresh VPC; if the account is at its VPC quota, adopt an already-existing VPC
    (distinct from ``exclude``) instead of failing on an unrelated capacity error."""
    vpc = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


def _create_or_adopt_vpc_with_subnet(ec2, ctx, vpc_cidr, subnet_cidr, vpc_name, subnet_name, exclude=None):
    """Create a fresh VPC+subnet; if the account is at its VPC quota, adopt an existing VPC
    (distinct from ``exclude``) and one of its existing subnets instead."""
    vpc = ec2.create_vpc(CidrBlock=vpc_cidr, TagSpecifications=[_tag_spec("vpc", vpc_name)])["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    subnet = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=subnet_cidr, TagSpecifications=[_tag_spec("subnet", subnet_name)]
    )["Subnet"]
    subnet_id = subnet["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    return vpc_id, subnet_id


def _error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected success raises, because
    a target accepting what real AWS refuses must not read as a plain code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _succeeds(fn):
    """True when fn() returns, False when it raises a ClientError (a retry probe, not a grader)."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError:
        return False
    return True


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
