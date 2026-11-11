"""describe-account-dedicated-tenancy-shape."""
from __future__ import annotations

import ipaddress

from behavioral_harness import tags

CHECK = "describe-account-dedicated-tenancy-shape"
GROUP = "control-plane"
SERVICES = ["workspaces"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAccount reports DedicatedTenancySupport as ENABLED or DISABLED, the same value on a second
    read, and a DedicatedTenancyManagementCidrRange only when ENABLED: none when DISABLED, a strict /16
    network when ENABLED.
    """
    ws = ctx.client("workspaces")
    account = ws.describe_account()

    support = account.get("DedicatedTenancySupport")
    assert support in ("ENABLED", "DISABLED"), f"unexpected DedicatedTenancySupport: {support}"

    # Read-only call: a second independent read must agree with the first. Catches a target
    # that fabricates a fresh (and possibly different) answer per call instead of reporting
    # actual account state.
    again = ws.describe_account()
    assert again.get("DedicatedTenancySupport") == support, (
        f"DescribeAccount is not stable across reads: {support!r} then "
        f"{again.get('DedicatedTenancySupport')!r}"
    )

    cidr = account.get("DedicatedTenancyManagementCidrRange")
    if support == "DISABLED":
        # No management network has ever been configured, so there is nothing to report.
        # A stub that echoes some other-service default (e.g. an empty string) still fails
        # this, since only `None` satisfies it.
        assert cidr is None, f"expected no management CIDR range while DISABLED, got {cidr!r}"
    else:
        assert cidr is not None, "expected a management CIDR range while ENABLED"
        net = ipaddress.ip_network(cidr, strict=True)
        assert net.prefixlen == 16, f"expected a /16 management CIDR range, got {cidr}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
