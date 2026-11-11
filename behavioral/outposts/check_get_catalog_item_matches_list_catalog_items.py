"""get-catalog-item-matches-list-catalog-items."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-catalog-item-matches-list-catalog-items"
GROUP = "catalog"
SERVICES = ["outposts"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCatalogItem for an item ID surfaced by ListCatalogItems returns a record with the
    same CatalogItemId (cross-checks that the two read paths agree on the same catalog)."""
    outposts = ctx.client("outposts")
    page = outposts.list_catalog_items(MaxResults=10)
    items = page.get("CatalogItems", [])
    if not items:
        raise AssertionError(
            "ListCatalogItems returned no items for this account/region; GetCatalogItem "
            "consistency cannot be exercised without at least one visible catalog entry "
            "(catalog visibility can depend on account Outposts enablement)."
        )

    summary = items[0]
    catalog_item_id = summary["CatalogItemId"]
    got = outposts.get_catalog_item(CatalogItemId=catalog_item_id)["CatalogItem"]
    assert got["CatalogItemId"] == catalog_item_id, (
        f"GetCatalogItem({catalog_item_id!r}) returned CatalogItemId={got.get('CatalogItemId')!r}, "
        f"expected the id it was asked for"
    )
    # ListCatalogItemsOutput.CatalogItems is modelled as the SAME CatalogItem shape GetCatalogItem
    # returns, so every field the list page reports must agree field-for-field with the direct read.
    for field, expected in summary.items():
        actual = got.get(field)
        assert actual == expected, (
            f"GetCatalogItem({catalog_item_id!r}) disagrees with ListCatalogItems on {field!r}: "
            f"list reported {expected!r}, get returned {actual!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
