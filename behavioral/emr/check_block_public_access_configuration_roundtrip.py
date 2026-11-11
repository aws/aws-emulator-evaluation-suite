"""block-public-access-configuration-roundtrip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "block-public-access-configuration-roundtrip"
GROUP = 'policies'
SERVICES = ['emr']


def _swallow(fn):
    """Run fn(), swallowing any exception. Teardown-only — never an assertion."""
    fn()


def _poll_until_ranges_match(emr, expected_ranges, *, timeout_s=60.0, interval_s=2.0):
    """Poll GetBlockPublicAccessConfiguration until the ranges list matches; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = emr.get_block_public_access_configuration()["BlockPublicAccessConfiguration"]
        if last.get("PermittedPublicSecurityGroupRuleRanges") == expected_ranges:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"PermittedPublicSecurityGroupRuleRanges did not converge to {expected_ranges!r} "
        f"within {timeout_s}s of Put; last observed {last!r}"
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:emr-block-public-access")
def run(ctx) -> None:
    """PutBlockPublicAccessConfiguration changes are reflected exactly by an independent
    GetBlockPublicAccessConfiguration: the submitted list replaces, not merges with, the prior one.
    """
    emr = ctx.client("emr")
    # One configuration per account and region: capture it and register the restore first.
    original = emr.get_block_public_access_configuration()["BlockPublicAccessConfiguration"]
    ctx.on_cleanup(
        lambda: _swallow(
            lambda: emr.put_block_public_access_configuration(
                BlockPublicAccessConfiguration=original
            )
        )
    )

    # Outside the documented default exception (port 22), so a merge cannot satisfy equality.
    submitted_ranges = [{"MinRange": 58000, "MaxRange": 58010}]
    emr.put_block_public_access_configuration(
        BlockPublicAccessConfiguration={
            "BlockPublicSecurityGroupRules": True,
            "PermittedPublicSecurityGroupRuleRanges": submitted_ranges,
        }
    )

    got = _poll_until_ranges_match(emr, submitted_ranges)
    assert got["BlockPublicSecurityGroupRules"] is True, (
        f"expected BlockPublicSecurityGroupRules to round-trip as True, got "
        f"{got['BlockPublicSecurityGroupRules']!r}"
    )
    assert got["PermittedPublicSecurityGroupRuleRanges"] == submitted_ranges, (
        f"expected PermittedPublicSecurityGroupRuleRanges to round-trip as exactly "
        f"{submitted_ranges!r}, got {got['PermittedPublicSecurityGroupRuleRanges']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
