"""network-acl-entry-ipv6-cidr-and-icmp-type-code-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "network-acl-entry-ipv6-cidr-and-icmp-type-code-round-trip"
GROUP = "vpc-networking"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A network ACL entry for the ICMP protocol carries IcmpTypeCode instead of PortRange, and
    an entry for an IPv6 range carries Ipv6CidrBlock instead of CidrBlock; deleting either entry
    removes it from a later DescribeNetworkAcls read.
    """
    ec2 = ctx.client("ec2")
    vpc_id = ctx.network().vpc_id

    acl = ec2.create_network_acl(
        VpcId=vpc_id,
        TagSpecifications=[
            {
                "ResourceType": "network-acl",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nacl-")}],
            }
        ],
    )["NetworkAcl"]
    acl_id = acl["NetworkAclId"]
    ctx.on_cleanup(lambda: ec2.delete_network_acl(NetworkAclId=acl_id))

    ec2.create_network_acl_entry(
        NetworkAclId=acl_id,
        RuleNumber=100,
        Protocol="1",
        RuleAction="allow",
        Egress=False,
        CidrBlock="203.0.113.0/24",
        IcmpTypeCode={"Type": 8, "Code": -1},
    )
    ec2.create_network_acl_entry(
        NetworkAclId=acl_id,
        RuleNumber=110,
        Protocol="6",
        RuleAction="allow",
        Egress=False,
        Ipv6CidrBlock="2001:db8::/32",  # RFC 3849 documentation prefix
        PortRange={"From": 443, "To": 443},
    )

    # DescribeNetworkAcls is eventually consistent: poll until both new entries are visible
    # rather than asserting on a single, possibly-stale read.
    entries = _poll_until(
        lambda: ec2.describe_network_acls(NetworkAclIds=[acl_id])["NetworkAcls"][0]["Entries"],
        lambda es: {100, 110} <= {e["RuleNumber"] for e in es if not e["Egress"]},
        timeout_s=30.0,
    )

    icmp_entry = next(e for e in entries if e["RuleNumber"] == 100 and not e["Egress"])
    assert icmp_entry.get("IcmpTypeCode") == {"Type": 8, "Code": -1}, (
        f"expected IcmpTypeCode {{'Type': 8, 'Code': -1}}, got {icmp_entry.get('IcmpTypeCode')!r}"
    )
    assert icmp_entry.get("CidrBlock") == "203.0.113.0/24", (
        f"expected CidrBlock '203.0.113.0/24', got {icmp_entry.get('CidrBlock')!r}"
    )
    assert "PortRange" not in icmp_entry, f"an ICMP entry must not carry a PortRange: {icmp_entry}"

    v6_entry = next(e for e in entries if e["RuleNumber"] == 110 and not e["Egress"])
    assert v6_entry.get("Ipv6CidrBlock") == "2001:db8::/32", (
        f"expected Ipv6CidrBlock '2001:db8::/32', got {v6_entry.get('Ipv6CidrBlock')!r}"
    )
    assert "CidrBlock" not in v6_entry, f"an IPv6 entry must not carry a CidrBlock: {v6_entry}"
    assert v6_entry.get("PortRange") == {"From": 443, "To": 443}, (
        f"expected PortRange 443-443, got {v6_entry.get('PortRange')!r}"
    )

    ec2.delete_network_acl_entry(NetworkAclId=acl_id, RuleNumber=100, Egress=False)
    ec2.delete_network_acl_entry(NetworkAclId=acl_id, RuleNumber=110, Egress=False)

    remaining = _poll_until(
        lambda: ec2.describe_network_acls(NetworkAclIds=[acl_id])["NetworkAcls"][0]["Entries"],
        lambda es: not any(e["RuleNumber"] in (100, 110) for e in es),
        timeout_s=30.0,
    )
    assert not any(e["RuleNumber"] in (100, 110) for e in remaining), (
        f"deleted entries still present: {remaining}"
    )


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
