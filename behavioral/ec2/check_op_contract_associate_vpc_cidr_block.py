"""op-contract-associateVpcCidrBlock."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-associateVpcCidrBlock"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateVpcCidrBlock grows a VPC's IPv4 space; a nonexistent VPC is rejected."""
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-assocvpc-")
    vpc = ec2.create_vpc(
        CidrBlock="10.198.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc))

    # error boundary: VPC does not exist
    code, message = _error_of(lambda: ec2.associate_vpc_cidr_block(VpcId="vpc-00000000000000000", CidrBlock="10.99.0.0/16"))
    assert code == "InvalidVpcID.NotFound", f"expected InvalidVpcID.NotFound, got {code!r}"
    assert message == "vpc-00000000000000000 is not found for user.", message

    # success path: associate a secondary, non-overlapping IPv4 CIDR block
    resp = ec2.associate_vpc_cidr_block(VpcId=vpc, CidrBlock="10.199.0.0/16")
    assoc = resp["CidrBlockAssociation"]
    assoc_id = assoc["AssociationId"]
    assert assoc["CidrBlock"] == "10.199.0.0/16", (
        f"expected the association to echo 10.199.0.0/16, got {assoc['CidrBlock']}"
    )
    assert assoc["CidrBlockState"]["State"] in ("associating", "associated"), (
        f"expected associating|associated on create, got {assoc['CidrBlockState']['State']!r}"
    )

    def cleanup_assoc():
        try:
            ec2.disassociate_vpc_cidr_block(AssociationId=assoc_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVpcCidrBlockAssociationID.NotFound":
                raise

    ctx.on_cleanup(cleanup_assoc)

    final = _poll_until(
        lambda: [
            a
            for a in ec2.describe_vpcs(VpcIds=[vpc])["Vpcs"][0]["CidrBlockAssociationSet"]
            if a["AssociationId"] == assoc_id
        ],
        lambda rows: bool(rows) and rows[0]["CidrBlockState"]["State"] == "associated",
        timeout_s=60,
        interval_s=2,
    )
    assert final[0]["CidrBlockState"]["State"] == "associated", (
        f"expected the secondary CIDR to settle on associated, got {final[0]['CidrBlockState']['State']!r}"
    )


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_of(fn: Callable[[], Any]) -> tuple[str | None, str | None]:
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
