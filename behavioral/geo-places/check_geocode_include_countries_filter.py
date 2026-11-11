"""geocode-include-countries-filter."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "geocode-include-countries-filter"
GROUP = "search"
SERVICES = ["geo-places"]


@tags("axis:happy-path", "cap:c2", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Geocode for 'Paris' resolves to France without a filter, and with Filter.IncludeCountries USA returns
    only results whose country Code3 is USA.
    """
    geo = ctx.client("geo-places")

    default_resp = geo.geocode(QueryText="Paris", MaxResults=5)
    default_items = default_resp.get("ResultItems", [])
    assert default_items, "expected a default (unfiltered) Geocode match for 'Paris'"
    default_codes = {item["Address"]["Country"]["Code3"] for item in default_items}
    assert "FRA" in default_codes, (
        "expected the unfiltered 'Paris' query to resolve to France among its matches "
        f"(needed to prove Filter.IncludeCountries=['USA'] changes anything), got {default_codes}"
    )

    resp = geo.geocode(
        QueryText="Paris",
        Filter={"IncludeCountries": ["USA"]},
        MaxResults=5,
    )
    items = resp.get("ResultItems", [])
    assert items, "expected Geocode to return a USA-filtered match for 'Paris'"
    for item in items:
        country = item["Address"]["Country"]
        assert country["Code3"] == "USA", (
            f"Filter.IncludeCountries=['USA'] leaked a non-US result: {country}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
