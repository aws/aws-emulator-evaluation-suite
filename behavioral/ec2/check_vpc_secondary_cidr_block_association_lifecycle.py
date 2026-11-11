"""vpc-secondary-cidr-block-association-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vpc-secondary-cidr-block-association-lifecycle"
GROUP = 'vpc-subnet'
SERVICES = ['ec2']

ERR_NOT_PERMITTED = 'OperationNotPermitted'
# Disassociating a secondary CIDR that still contains a subnet is
# NOT the generic InvalidParameterValue -- EC2 has a dedicated code for it, InvalidCidrBlock.InUse
# ("The vpc vpc-... currently has a subnet within CIDR block 10.142.0.0/16"), distinct from the
# OperationNotPermitted that guards the primary CIDR. The two refusals are different failures and
# real EC2 keeps them separate, so the check asserts both codes and that they differ.
ERR_CIDR_IN_USE = 'InvalidCidrBlock.InUse'
PRIMARY_CIDR = '10.141.0.0/16'
SECONDARY_CIDR = '10.142.0.0/16'
SECONDARY_SUBNET_CIDR = '10.142.1.0/24'


def _delete_gone_ok(fn, gone_code):
    """Teardown: the body deletes the resource itself, so its not-found answer is done."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != gone_code:
            raise


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _wait_vpc_available(ec2, vpc_id, timeout_s=90):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"]
        if last == "available":
            return
        time.sleep(2)
    raise AssertionError(f"vpc {vpc_id} never reached available in {timeout_s}s (last {last!r})")


def _assoc_set(ec2, vpc_id):
    """{cidr: state} over the VPC's live (non-disassociated) CIDR block associations."""
    vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    out = {}
    for a in vpc.get("CidrBlockAssociationSet", []):
        state = a["CidrBlockState"]["State"]
        if state != "disassociated":
            out[a["CidrBlock"]] = state
    return out


def _assoc_id(ec2, vpc_id, cidr):
    vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    for a in vpc.get("CidrBlockAssociationSet", []):
        if a["CidrBlock"] == cidr and a["CidrBlockState"]["State"] != "disassociated":
            return a["AssociationId"]
    raise AssertionError(f"vpc {vpc_id} has no live association for {cidr}")


def _wait_cidr_state(ec2, vpc_id, cidr, state, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _assoc_set(ec2, vpc_id).get(cidr)
        if last == state:
            return
        time.sleep(3)
    raise AssertionError(
        f"vpc {vpc_id} CIDR {cidr} never reached {state!r} in {timeout_s}s (last {last!r})"
    )


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateVpcCidrBlock adds a second CIDR with its own association id to a live VPC; disassociating
    the primary CIDR, or a secondary one that still holds a subnet, fails with distinct codes and
    messages; once the subnet is deleted the secondary disassociates and only the primary remains."""
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": "1"}]

    vpc_id = ec2.create_vpc(
        CidrBlock=PRIMARY_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    _wait_vpc_available(ec2, vpc_id)

    initial = _assoc_set(ec2, vpc_id)
    assert initial == {PRIMARY_CIDR: "associated"}, (
        f"a fresh VPC must expose exactly its primary CIDR as an association, got {initial}"
    )
    primary_assoc_id = _assoc_id(ec2, vpc_id, PRIMARY_CIDR)

    # --- associate a secondary CIDR: new association id, associating -> associated ---
    assoc = ec2.associate_vpc_cidr_block(VpcId=vpc_id, CidrBlock=SECONDARY_CIDR)[
        "CidrBlockAssociation"
    ]
    secondary_assoc_id = assoc["AssociationId"]
    ctx.on_cleanup(
        lambda: ec2.disassociate_vpc_cidr_block(AssociationId=secondary_assoc_id)
    )
    assert secondary_assoc_id.startswith("vpc-cidr-assoc-"), (
        f"expected a vpc-cidr-assoc- id, got {secondary_assoc_id!r}"
    )
    assert secondary_assoc_id != primary_assoc_id, "secondary association reused the primary's id"
    assert assoc["CidrBlockState"]["State"] in ("associating", "associated"), (
        f"expected associating|associated on create, got {assoc['CidrBlockState']['State']!r}"
    )
    _wait_cidr_state(ec2, vpc_id, SECONDARY_CIDR, "associated")

    vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    assert _assoc_set(ec2, vpc_id) == {PRIMARY_CIDR: "associated", SECONDARY_CIDR: "associated"}, (
        f"expected both CIDRs associated, got {_assoc_set(ec2, vpc_id)}"
    )
    assert vpc["CidrBlock"] == PRIMARY_CIDR, (
        f"the scalar CidrBlock must stay the PRIMARY CIDR, got {vpc['CidrBlock']}"
    )

    # --- the secondary range is genuinely routable: a subnet can be cut from it ---
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=SECONDARY_SUBNET_CIDR,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_gone_ok(lambda: ec2.delete_subnet(SubnetId=subnet_id), "InvalidSubnetID.NotFound"))
    subnet = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]
    assert subnet["CidrBlock"] == SECONDARY_SUBNET_CIDR and subnet["VpcId"] == vpc_id, (
        f"subnet in the secondary range must echo {SECONDARY_SUBNET_CIDR} on {vpc_id}, got {subnet}"
    )

    # --- negative 1: the primary CIDR association is undroppable ---
    primary_message = None
    try:
        ec2.disassociate_vpc_cidr_block(AssociationId=primary_assoc_id)
    except ClientError as exc:
        assert _code(exc) == ERR_NOT_PERMITTED, (
            f"expected {ERR_NOT_PERMITTED} disassociating the primary CIDR, got {_code(exc)}"
        )
        primary_message = exc.response.get("Error", {}).get("Message", "")
        expected = (
            f"The vpc CIDR block with association ID {primary_assoc_id} may not be disassociated. "
            "It is the primary IPv4 CIDR block of the VPC"
        )
        assert primary_message == expected, (
            f"the refusal must name the association it refused ({primary_assoc_id}) as the VPC's "
            f"primary CIDR block, got {primary_message!r}"
        )
    else:
        raise AssertionError(
            f"disassociating the primary CIDR {PRIMARY_CIDR} must be rejected, it succeeded"
        )
    assert _assoc_set(ec2, vpc_id) == {PRIMARY_CIDR: "associated", SECONDARY_CIDR: "associated"}, (
        f"rejected primary disassociate must not change the association set, got {_assoc_set(ec2, vpc_id)}"
    )

    # --- negative 2: a secondary CIDR still carrying a subnet is undroppable ---
    try:
        ec2.disassociate_vpc_cidr_block(AssociationId=secondary_assoc_id)
    except ClientError as exc:
        assert _code(exc) == ERR_CIDR_IN_USE, (
            f"expected {ERR_CIDR_IN_USE} disassociating an in-use secondary CIDR, got {_code(exc)}"
        )
        in_use_message = exc.response.get("Error", {}).get("Message", "")
        assert SECONDARY_CIDR in in_use_message, (
            f"the in-use refusal must name the CIDR block that is occupied ({SECONDARY_CIDR}), "
            f"got {in_use_message!r}"
        )
        assert "subnet" in in_use_message, (
            f"the in-use refusal must say a subnet is what occupies the range, got "
            f"{in_use_message!r}"
        )
        assert _code(exc) != ERR_NOT_PERMITTED, (
            f"an occupied secondary CIDR and the undroppable primary CIDR are different "
            f"refusals, but both answered {ERR_NOT_PERMITTED}"
        )
        assert in_use_message != primary_message, (
            f"the occupied-secondary and primary-CIDR refusals produced the identical "
            f"diagnostic {in_use_message!r}"
        )
    else:
        raise AssertionError(
            f"disassociating {SECONDARY_CIDR} while subnet {subnet_id} occupies it must be rejected"
        )
    assert _assoc_set(ec2, vpc_id).get(SECONDARY_CIDR) == "associated", (
        f"rejected secondary disassociate must leave it associated, got {_assoc_set(ec2, vpc_id)}"
    )

    # --- control: remove the dependent subnet, then the secondary CIDR drops cleanly ---
    ec2.delete_subnet(SubnetId=subnet_id)
    try:
        ec2.describe_subnets(SubnetIds=[subnet_id])
    except ClientError as exc:
        assert _code(exc) == "InvalidSubnetID.NotFound", (
            f"expected InvalidSubnetID.NotFound reading the deleted subnet, got {_code(exc)}"
        )
        gone_message = exc.response.get("Error", {}).get("Message", "")
        assert gone_message == f"The subnet ID '{subnet_id}' does not exist", gone_message
    else:
        raise AssertionError(f"subnet {subnet_id} must be gone after DeleteSubnet, describe still answers")
    ec2.disassociate_vpc_cidr_block(AssociationId=secondary_assoc_id)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline and SECONDARY_CIDR in _assoc_set(ec2, vpc_id):
        time.sleep(3)
    final = _assoc_set(ec2, vpc_id)
    assert final == {PRIMARY_CIDR: "associated"}, (
        f"after disassociating {SECONDARY_CIDR} only the primary must remain, got {final}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
