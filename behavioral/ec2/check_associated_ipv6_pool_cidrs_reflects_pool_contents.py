"""associated-ipv6-pool-cidrs-reflects-pool-contents."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associated-ipv6-pool-cidrs-reflects-pool-contents"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAssociatedIpv6PoolCidrs returns no CIDR associations (an error or an empty list) for a vpc-* id and for
    a well-formed unknown ipv6pool-ec2-* id; a real pool needs a BYOIP IPv6 range no account can make on demand.
    """
    ec2 = ctx.client("ec2")

    # A PoolId from a completely different resource-ID family must never
    # yield fabricated CIDRs: either the call is rejected outright, or it
    # answers with an empty association set.
    code = None
    resp = None
    try:
        resp = ec2.get_associated_ipv6_pool_cidrs(PoolId="vpc-00000000000000000")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
    if resp is not None:
        got = resp.get("Ipv6CidrAssociations", [])
        assert got == [], (
            "PoolId from a different resource-ID family (vpc-*) must not "
            f"yield fabricated CIDR associations; expected [], got {got!r}"
        )
    else:
        assert code is not None, (
            "expected either a ClientError or an empty association set for "
            "a vpc-* PoolId, got neither (resp and code both None)"
        )

    # A well-formed but nonexistent pool ID must never yield fabricated CIDRs.
    code = None
    resp = None
    try:
        resp = ec2.get_associated_ipv6_pool_cidrs(PoolId="ipv6pool-ec2-0123456789abcdef0")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
    if resp is not None:
        got = resp.get("Ipv6CidrAssociations", [])
        assert got == [], (
            "a well-formed but nonexistent ipv6pool-ec2-* PoolId must not "
            f"yield fabricated CIDR associations; expected [], got {got!r}"
        )
    else:
        assert code is not None, (
            "expected either a ClientError or an empty association set for "
            "a nonexistent ipv6pool-ec2-* PoolId, got neither (resp and code "
            "both None)"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
