"""search-text-bounding-box-filter."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-text-bounding-box-filter"
GROUP = "search"
SERVICES = ["geo-places"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SearchText's Filter.BoundingBox restricts every result's Position to inside the box."""
    geo = ctx.client("geo-places")
    # A small box around downtown Seattle that contains the Space Needle.
    west, south, east, north = -122.36, 47.60, -122.33, 47.62
    resp = geo.search_text(
        QueryText="coffee",
        Filter={"BoundingBox": [west, south, east, north]},
        MaxResults=10,
    )
    items = resp.get("ResultItems", [])
    assert items, "expected SearchText to find coffee shops inside the bounding box"
    for item in items:
        lng, lat = item["Position"]
        assert west <= lng <= east, f"{item['Title']} longitude {lng} outside BoundingBox"
        assert south <= lat <= north, f"{item['Title']} latitude {lat} outside BoundingBox"

    # Negative control: an identical query over open ocean, where no coffee shop can
    # exist, must come back empty. Without this, a target that ignores Filter and
    # always returns the same fixed Seattle result set would still pass above.
    ocean_box = [-140.10, 30.00, -140.08, 30.02]
    ocean_resp = geo.search_text(
        QueryText="coffee",
        Filter={"BoundingBox": ocean_box},
        MaxResults=10,
    )
    ocean_items = ocean_resp.get("ResultItems", [])
    assert not ocean_items, (
        f"expected no coffee results in an open-ocean BoundingBox, got "
        f"{[i['Title'] for i in ocean_items]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
