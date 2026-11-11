"""checker-ip-ranges-stable-server-managed-list."""
from __future__ import annotations

import ipaddress

from behavioral_harness import tags

CHECK = "checker-ip-ranges-stable-server-managed-list"
GROUP = "server-side"
SERVICES = ["route53"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCheckerIpRanges returns a non-empty, server-managed CIDR list -- it takes
    no client-supplied input, and repeated calls return the identical list."""
    route53 = ctx.client("route53")

    first = route53.get_checker_ip_ranges()["CheckerIpRanges"]
    assert len(first) > 0, "expected a non-empty list of checker IP ranges"
    for cidr in first:
        # Raises ValueError if this isn't a well-formed CIDR block.
        network = ipaddress.ip_network(cidr, strict=True)
        assert network.prefixlen > 0, f"{cidr!r} is a degenerate default-route block"

    second = route53.get_checker_ip_ranges()["CheckerIpRanges"]
    assert second == first, "checker IP ranges changed between two back-to-back calls"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
