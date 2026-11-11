"""static-catalog-reads-are-not-hollow-200s."""
# A service's static catalog reads must return populated, well-formed catalogs -- a 200 carrying an empty
# document is a stub, not an answer.
#
# SCOPED DELIBERATELY TO READ-ONLY CATALOG OPERATIONS. Contact methods are not used here: creating one
# sends a real verification email or SMS to an address, which a check must not cause, and reading
# them legitimately returns nothing on an account that has none -- so an empty answer there is CORRECT and
# unassertable.
#
# GetRegions / GetBlueprints / GetBundles are the right instrument instead: each returns a substantial
# static catalog that cannot legitimately be empty, and all three are pure reads with nothing to create,
# bill or clean up. Floors rather than exact counts, because AWS grows these catalogs and pinning a count
# would break on the next region or blueprint shipped.
from __future__ import annotations

from behavioral_harness import tags

CHECK = "static-catalog-reads-are-not-hollow-200s"
GROUP = "coverage"
SERVICES = ["lightsail"]

# Floors, not exact counts: AWS grows these catalogs, and pinning a count would break on the next
# region or blueprint AWS ships. Each floor is far below the observed size and far above zero, which is
# the only distinction this check needs to make.
MIN_REGIONS = 5
MIN_BLUEPRINTS = 5
MIN_BUNDLES = 5


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRegions (including the check's region), GetBlueprints and GetBundles each return at least 5
    well-formed entries, and every bundle has positive RAM and price.
    """
    ls = ctx.client("lightsail")

    # --- Beat 1: GetRegions -------------------------------------------------------------------------
    regions = ls.get_regions().get("regions") or []
    assert len(regions) >= MIN_REGIONS, (
        f"GetRegions must return Lightsail's region catalog; got {len(regions)} entries "
        f"({regions!r}). A 200 carrying an empty document is a stub answering for an unimplemented "
        f"operation"
    )
    # Shape, not just cardinality: a target could return N empty objects and satisfy a count.
    for region in regions:
        assert region.get("name") and region.get("continentCode"), (
            f"every region entry must carry a name and a continentCode, got {region!r}"
        )
    assert ctx.region in {r["name"] for r in regions}, (
        f"the catalog must include the region this client is configured for ({ctx.region!r}); got "
        f"{sorted(r['name'] for r in regions)!r}"
    )

    # --- Beat 2: GetBlueprints -- a second, independent catalog ------------------------------------
    # Independent because stubbing is per-operation: one path correct while another in the
    # same service is hollow.
    blueprints = ls.get_blueprints().get("blueprints") or []
    assert len(blueprints) >= MIN_BLUEPRINTS, (
        f"GetBlueprints must return the blueprint catalog; got {len(blueprints)} entries"
    )
    for blueprint in blueprints:
        assert blueprint.get("blueprintId") and blueprint.get("type"), (
            f"every blueprint must carry a blueprintId and a type, got {blueprint!r}"
        )

    # --- Beat 3: GetBundles -- a third, and one carrying NUMERIC fields ----------------------------
    # The numeric fields matter: a stub that synthesises string-only placeholders satisfies Beats 1-2
    # but cannot produce a coherent price/RAM pair.
    bundles = ls.get_bundles().get("bundles") or []
    assert len(bundles) >= MIN_BUNDLES, (
        f"GetBundles must return the bundle catalog; got {len(bundles)} entries"
    )
    for bundle in bundles:
        assert bundle.get("bundleId"), f"every bundle must carry a bundleId, got {bundle!r}"
        assert isinstance(bundle.get("ramSizeInGb"), (int, float)) and bundle["ramSizeInGb"] > 0, (
            f"a bundle must state a positive RAM size, got {bundle.get('ramSizeInGb')!r} in "
            f"{bundle!r}"
        )
        assert isinstance(bundle.get("price"), (int, float)) and bundle["price"] > 0, (
            f"a bundle must state a positive price, got {bundle.get('price')!r} in {bundle!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
