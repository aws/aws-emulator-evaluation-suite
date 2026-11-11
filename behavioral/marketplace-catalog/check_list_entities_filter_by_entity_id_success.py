"""list-entities-filter-by-entity-id-success."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-entities-filter-by-entity-id-success"
GROUP = "data-plane"
SERVICES = ["marketplace-catalog"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListEntities filtered by a fabricated, nonexistent EntityId returns an empty EntitySummaryList."""
    # The Marketplace Catalog API is served only in us-east-1, so every target is called there.
    mp = ctx.client("marketplace-catalog", region="us-east-1")

    fake_id = "prod-" + ctx.unique_name("sim2realbehav").replace("-", "")
    resp = mp.list_entities(
        Catalog="AWSMarketplace",
        EntityType="AmiProduct",
        FilterList=[{"Name": "EntityId", "ValueList": [fake_id]}],
    )
    assert resp["EntitySummaryList"] == [], "filtering by an unknown EntityId must yield no results"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
