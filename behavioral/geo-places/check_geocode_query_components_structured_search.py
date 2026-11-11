"""geocode-query-components-structured-search."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "geocode-query-components-structured-search"
GROUP = "geocoding"
SERVICES = ["geo-places"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Geocode accepts a structured QueryComponents input (no free-text QueryText) and
    resolves it to the matching place."""
    geo = ctx.client("geo-places")
    resp = geo.geocode(
        QueryComponents={"Country": "USA", "Region": "Washington", "Locality": "Seattle"},
        MaxResults=5,
    )
    items = resp.get("ResultItems", [])
    assert items, "expected Geocode to resolve a structured QueryComponents query"
    for item in items:
        country = item["Address"]["Country"]
        assert country["Code3"] == "USA", f"expected USA, got {country}"
    localities = [item["Address"].get("Locality", "") for item in items]
    assert any("seattle" in loc.lower() for loc in localities), (
        f"expected a Seattle locality among results, got {localities}"
    )

    # Region.Code is a normalized abbreviation the service derives from the
    # full "Washington" name we sent, not an echo of the request.
    top = items[0]
    region_code = top["Address"].get("Region", {}).get("Code")
    assert region_code == "WA", f"expected Region.Code WA (from 'Washington'), got {region_code}"

    # Position is real-world coordinates the request never supplied, so a
    # target that just echoed the input components back could not fake this.
    longitude, latitude = top["Position"]
    assert 47.4 <= latitude <= 47.8, f"expected Seattle-area latitude, got {latitude}"
    assert -122.6 <= longitude <= -122.05, f"expected Seattle-area longitude, got {longitude}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
