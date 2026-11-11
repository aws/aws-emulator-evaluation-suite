"""block-public-access-configuration-exception-list-precision-preserved."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "block-public-access-configuration-exception-list-precision-preserved"
GROUP = "representation"
SERVICES = ["emr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:emr-block-public-access")
def run(ctx) -> None:
    """Port-range exceptions written via PutBlockPublicAccessConfiguration round-trip with exact bounds."""
    emr = ctx.client("emr")

    original = emr.get_block_public_access_configuration()["BlockPublicAccessConfiguration"]
    ctx.on_cleanup(lambda: emr.put_block_public_access_configuration(BlockPublicAccessConfiguration=original))

    ranges = [
        {"MinRange": 22, "MaxRange": 22},
        {"MinRange": 8000, "MaxRange": 8999},
        {"MinRange": 65535, "MaxRange": 65535},
    ]
    emr.put_block_public_access_configuration(
        BlockPublicAccessConfiguration={
            "BlockPublicSecurityGroupRules": True,
            "PermittedPublicSecurityGroupRuleRanges": ranges,
        }
    )

    fetched = emr.get_block_public_access_configuration()["BlockPublicAccessConfiguration"]
    assert fetched["BlockPublicSecurityGroupRules"] is True, (
        f"BlockPublicSecurityGroupRules must round-trip as True, got {fetched['BlockPublicSecurityGroupRules']!r}"
    )
    fetched_ranges = fetched["PermittedPublicSecurityGroupRuleRanges"]
    assert len(fetched_ranges) == len(ranges), (
        f"expected {len(ranges)} permitted ranges, got {len(fetched_ranges)}: {fetched_ranges!r}"
    )
    for expected, actual in zip(ranges, fetched_ranges):
        assert actual["MinRange"] == expected["MinRange"], (
            f"expected MinRange {expected['MinRange']}, got {actual.get('MinRange')!r} in {actual!r}"
        )
        assert actual["MaxRange"] == expected["MaxRange"], (
            f"expected MaxRange {expected['MaxRange']}, got {actual.get('MaxRange')!r} in {actual!r}"
        )
    # A single-port exception (Min == Max) must not be silently widened or collapsed.
    single_port = [r for r in fetched_ranges if r["MinRange"] == 22]
    assert single_port and single_port[0]["MaxRange"] == 22, (
        f"expected a preserved single-port exception 22-22, got {single_port!r} in {fetched_ranges!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
