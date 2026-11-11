"""geocode-include-place-types-filter."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "geocode-include-place-types-filter"
GROUP = "search"
SERVICES = ["geo-places"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Geocode for 'Washington' returns a Region without a filter, and with Filter.IncludePlaceTypes Locality
    returns only Locality results.
    """
    geo = ctx.client("geo-places")
    unfiltered = geo.geocode(QueryText="Washington", MaxResults=5).get("ResultItems", [])
    unfiltered_types = {item["PlaceType"] for item in unfiltered}
    assert "Region" in unfiltered_types, (
        f"expected the unfiltered 'Washington' query to include a Region match "
        f"(control proving the filter has something to exclude), got {sorted(unfiltered_types)}"
    )

    resp = geo.geocode(
        QueryText="Washington",
        Filter={"IncludePlaceTypes": ["Locality"]},
        MaxResults=5,
    )
    items = resp.get("ResultItems", [])
    assert items, "expected Geocode to return Locality-filtered matches for 'Washington'"
    for item in items:
        assert item["PlaceType"] == "Locality", (
            f"Filter.IncludePlaceTypes=['Locality'] leaked a {item['PlaceType']} result"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
