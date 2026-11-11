"""list-available-management-cidr-ranges-shape."""
from __future__ import annotations

import ipaddress

from behavioral_harness import tags

CHECK = "list-available-management-cidr-ranges-shape"
GROUP = "control-plane"
SERVICES = ["workspaces"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAvailableManagementCidrRanges always returns /16 blocks (the
    DedicatedTenancyManagementCidrRange shape is pattern-locked to /16, not /26) that fall
    within the requested constraint CIDR."""
    ws = ctx.client("workspaces")
    ec2 = ctx.client("ec2")

    # The operation excludes candidates that overlap the account's existing VPCs, so a
    # constraint that collides with a VPC already present in a shared sandbox account can
    # legitimately come back empty. Pick a /16 that avoids every VPC CIDR this account
    # currently has, so an empty result can only mean the operation is broken, not that we
    # asked for an already-occupied block.
    used_nets = []
    for vpc in ec2.describe_vpcs(VpcIds=[ctx.network().vpc_id])["Vpcs"]:
        for assoc in vpc.get("CidrBlockAssociationSet", []):
            cidr = assoc.get("CidrBlock")
            if cidr:
                used_nets.append(ipaddress.ip_network(cidr))

    candidates = [f"10.{octet}.0.0/16" for octet in (250, 200, 150, 100, 50, 30, 10)] + [
        "172.20.0.0/16",
        "192.168.0.0/16",
    ]
    constraint = next(
        c
        for c in candidates
        if not any(ipaddress.ip_network(c).overlaps(u) for u in used_nets)
    )

    ranges = ws.list_available_management_cidr_ranges(
        ManagementCidrRangeConstraint=constraint
    )["ManagementCidrRanges"]

    assert isinstance(ranges, list), f"expected ManagementCidrRanges to be a list, got {type(ranges)}"
    assert ranges, (
        f"expected at least one available management CIDR range for constraint "
        f"{constraint} (chosen to avoid every existing VPC CIDR in this account), got an "
        f"empty list"
    )
    constraint_net = ipaddress.ip_network(constraint)
    for cidr in ranges:
        assert cidr.endswith("/16"), f"expected a /16 management CIDR, got {cidr}"
        net = ipaddress.ip_network(cidr)
        assert net.subnet_of(constraint_net), f"{cidr} is not within constraint {constraint}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
