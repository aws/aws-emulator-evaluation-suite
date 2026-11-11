"""list-controls-filter-by-governed-provider-matches."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-controls-filter-by-governed-provider-matches"
GROUP = "filtering"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListControls filtered by GovernedProviders=[AWS] returns only controls that govern AWS
    resources, and a syntactically valid but non-existent provider excludes everything — proving
    the filter narrows results rather than being ignored."""
    cc = ctx.client("controlcatalog")
    resp = cc.list_controls(Filter={"GovernedProviders": ["AWS"]}, MaxResults=50)
    controls = resp["Controls"]
    assert len(controls) > 0, "expected at least one AWS-governed control in the catalog"
    for c in controls:
        providers = c.get("GovernedProviders") or []
        assert "AWS" in providers, f"{c['Arn']}: GovernedProviders={providers}"

    bogus = cc.list_controls(
        Filter={"GovernedProviders": ["ZZNONEXISTENTPROVIDERZZ"]}, MaxResults=50
    )["Controls"]
    assert bogus == [], (
        f"GovernedProviders=[ZZNONEXISTENTPROVIDERZZ] returned {len(bogus)} controls; "
        "expected the filter to exclude everything for a provider no control governs, "
        "proving Filter is honored rather than ignored"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
