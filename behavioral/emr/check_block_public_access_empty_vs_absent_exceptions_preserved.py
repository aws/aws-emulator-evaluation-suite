"""block-public-access-empty-vs-absent-exceptions-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "block-public-access-empty-vs-absent-exceptions-preserved"
GROUP = "representation"
SERVICES = ["emr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:emr-block-public-access")
def run(ctx) -> None:
    """PutBlockPublicAccessConfiguration is a full replace: an explicit [] round-trips as empty, and
    omitting the ranges after a non-empty Put clears them rather than preserving them or
    reapplying the port-22 default.
    """
    emr = ctx.client("emr")
    # One configuration per account and region: capture it and restore it on cleanup.
    original = emr.get_block_public_access_configuration()["BlockPublicAccessConfiguration"]
    ctx.on_cleanup(lambda: emr.put_block_public_access_configuration(BlockPublicAccessConfiguration=original))

    ranges = [{"MinRange": 22, "MaxRange": 22}, {"MinRange": 8000, "MaxRange": 8010}]
    emr.put_block_public_access_configuration(
        BlockPublicAccessConfiguration={
            "BlockPublicSecurityGroupRules": True,
            "PermittedPublicSecurityGroupRuleRanges": ranges,
        }
    )
    populated_case = emr.get_block_public_access_configuration()["BlockPublicAccessConfiguration"]
    got_ranges = populated_case.get("PermittedPublicSecurityGroupRuleRanges")
    assert got_ranges == ranges, f"non-empty ranges did not round-trip exactly; got {got_ranges!r}"

    emr.put_block_public_access_configuration(
        BlockPublicAccessConfiguration={
            "BlockPublicSecurityGroupRules": True,
            "PermittedPublicSecurityGroupRuleRanges": [],
        }
    )
    empty_case = emr.get_block_public_access_configuration()["BlockPublicAccessConfiguration"]
    empty_ranges = empty_case.get("PermittedPublicSecurityGroupRuleRanges")
    assert empty_ranges == [], (
        f"explicit empty PermittedPublicSecurityGroupRuleRanges did not round-trip as "
        f"empty; got {empty_ranges!r} (the empty list was collapsed into a default)"
    )

    # The port-22 default applies only before any Put; an omitted field afterwards clears.
    emr.put_block_public_access_configuration(
        BlockPublicAccessConfiguration={
            "BlockPublicSecurityGroupRules": True,
            "PermittedPublicSecurityGroupRuleRanges": ranges,
        }
    )
    emr.put_block_public_access_configuration(
        BlockPublicAccessConfiguration={"BlockPublicSecurityGroupRules": True}
    )
    absent_case = emr.get_block_public_access_configuration()["BlockPublicAccessConfiguration"]
    absent_ranges = absent_case.get("PermittedPublicSecurityGroupRuleRanges")
    assert absent_ranges == [], (
        f"omitting PermittedPublicSecurityGroupRuleRanges after a prior non-empty Put "
        f"was expected to fully replace (clear) the ranges via a full-replace Put, "
        f"got {absent_ranges!r} -- looks like a merge/partial-update instead"
    )
    assert absent_ranges == empty_ranges, "omitted-field and explicit-empty-list cases must collapse to the identical canonical representation"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
