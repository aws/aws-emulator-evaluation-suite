"""checker-ip-ranges-stable-server-side-list."""
from __future__ import annotations

import ipaddress

from behavioral_harness import tags

CHECK = "checker-ip-ranges-stable-server-side-list"
GROUP = "server-side"
SERVICES = ["route53"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCheckerIpRanges (which takes no parameters) returns several distinct, strictly valid CIDRs
    and an identical list on an immediate repeat call."""
    route53 = ctx.client("route53")

    resp_1 = route53.get_checker_ip_ranges()
    resp_2 = route53.get_checker_ip_ranges()

    ranges_1 = resp_1["CheckerIpRanges"]
    ranges_2 = resp_2["CheckerIpRanges"]

    assert len(ranges_1) > 1, (
        f"expected a checker IP range list with more than one entry, got {ranges_1!r}"
    )
    assert len(set(ranges_1)) == len(ranges_1), (
        f"expected no duplicate CIDR entries, got {ranges_1!r}"
    )
    for cidr in ranges_1:
        # Raises ValueError on anything that is not well-formed CIDR notation.
        net = ipaddress.ip_network(cidr, strict=True)
        assert net.prefixlen > 0, f"found a degenerate default-route CIDR block: {cidr!r}"

    assert ranges_1 == ranges_2, "checker IP ranges must be stable across immediate repeated calls"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
