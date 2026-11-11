"""disassociate-vpc-cidr-block-primary-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "disassociate-vpc-cidr-block-primary-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]

ERR_NOT_PERMITTED = "OperationNotPermitted"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateVpcCidrBlock succeeds for a secondary CIDR block association, but is
    rejected (the primary CIDR block is immutable) when given the association ID of the
    VPC's original/primary CIDR block."""
    ec2 = ctx.client("ec2")

    vpc = ec2.create_vpc(CidrBlock="10.221.0.0/16", TagSpecifications=[_tag_spec("vpc", ctx.unique_name("sim2real-cidrvpc-"))])["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    primary_assoc_id = vpc["CidrBlockAssociationSet"][0]["AssociationId"]

    secondary = ec2.associate_vpc_cidr_block(VpcId=vpc_id, CidrBlock="10.222.0.0/16")
    secondary_assoc_id = secondary["CidrBlockAssociation"]["AssociationId"]

    def _assoc_state(assoc_id):
        described = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
        for assoc in described["CidrBlockAssociationSet"]:
            if assoc["AssociationId"] == assoc_id:
                return assoc["CidrBlockState"]["State"]
        return None

    _poll_until(
        lambda: _assoc_state(secondary_assoc_id),
        lambda s: s == "associated",
        timeout_s=60.0,
        interval_s=3.0,
        reason=f"secondary CIDR association {secondary_assoc_id} to reach associated",
    )

    # NEGATIVE: cannot disassociate the primary (VPC-creation-time) CIDR block.
    try:
        ec2.disassociate_vpc_cidr_block(AssociationId=primary_assoc_id)
        raise AssertionError("expected DisassociateVpcCidrBlock to reject the primary CIDR block association")
    except Exception as exc:  # noqa: BLE001 - inspect botocore ClientError specifically below
        from botocore.exceptions import ClientError

        assert isinstance(exc, ClientError), f"expected a ClientError, got {type(exc)}: {exc}"
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message", "")
        assert code == ERR_NOT_PERMITTED, f"expected {ERR_NOT_PERMITTED} rejecting the primary CIDR block, got {code!r} ({message!r})"
        assert message == (
            f"The vpc CIDR block with association ID {primary_assoc_id} may not be disassociated. "
            "It is the primary IPv4 CIDR block of the VPC"
        ), f"expected the rejection to reference the primary CIDR block, got: {message!r}"

    # Confirm the primary association is untouched (independent read).
    primary_state = _assoc_state(primary_assoc_id)
    assert primary_state == "associated", f"primary CIDR block association must remain untouched after the rejected call, got {primary_state!r}"

    # POSITIVE CONTROL: disassociating the secondary CIDR block succeeds, proving the
    # primary rejection above is specific to the primary association and not a blanket
    # denial of DisassociateVpcCidrBlock on this target.
    resp = ec2.disassociate_vpc_cidr_block(AssociationId=secondary_assoc_id)
    assert resp["VpcId"] == vpc_id, f"expected VpcId {vpc_id!r}, got {resp.get('VpcId')!r}"
    assert resp["CidrBlockAssociation"]["AssociationId"] == secondary_assoc_id, (
        f"expected AssociationId {secondary_assoc_id!r}, got {resp['CidrBlockAssociation'].get('AssociationId')!r}"
    )
    assert resp["CidrBlockAssociation"]["CidrBlockState"]["State"] in ("disassociating", "disassociated"), (
        f"expected disassociating|disassociated on the mutating response, got {resp['CidrBlockAssociation']['CidrBlockState']['State']!r}"
    )

    # TERMINAL READ: independent of the mutating call above — the secondary association must
    # actually leave the VPC's live association state.
    final_state = _poll_until(
        lambda: _assoc_state(secondary_assoc_id),
        lambda s: s in (None, "disassociated"),
        timeout_s=60.0,
        interval_s=3.0,
        reason=f"secondary CIDR association {secondary_assoc_id} to disassociate",
    )
    assert final_state in (None, "disassociated"), (
        f"expected the secondary association to disappear or read disassociated, got {final_state!r}"
    )


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=5.0, reason="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {reason} (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
