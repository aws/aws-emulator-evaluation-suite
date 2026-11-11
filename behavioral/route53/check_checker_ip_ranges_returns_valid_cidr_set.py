"""checker-ip-ranges-returns-valid-cidr-set."""
from __future__ import annotations

import ipaddress

from behavioral_harness import tags

CHECK = "checker-ip-ranges-returns-valid-cidr-set"
GROUP = "server-side"
SERVICES = ["route53"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCheckerIpRanges returns a non-empty, well-formed set of CIDR ranges."""
    r53 = ctx.client("route53")
    resp = r53.get_checker_ip_ranges()
    ranges = resp["CheckerIpRanges"]

    assert isinstance(ranges, list) and len(ranges) > 0, "expected a non-empty CIDR list"

    parsed = []
    for cidr in ranges:
        # Raises ValueError if this isn't a well-formed CIDR block.
        parsed.append(ipaddress.ip_network(cidr, strict=True))

    # The checker ranges should be well-formed public/allocatable IPv4 or IPv6 blocks,
    # not degenerate placeholders like 0.0.0.0/0.
    assert all(net.prefixlen > 0 for net in parsed), "found a default-route CIDR block"
    # No duplicate entries in the published set.
    assert len(set(ranges)) == len(ranges), "duplicate CIDR entries in CheckerIpRanges"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
