"""concurrent-getplace-calls-consistent."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-getplace-calls-consistent"
GROUP = "concurrency"
SERVICES = ["geo-places"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Many concurrent GetPlace reads for the same PlaceId return identical data.

    GetPlace is a pure read; under concurrent load a faithful backend must never
    mix up or corrupt responses across in-flight requests for the same resource.
    """
    geo = ctx.client("geo-places")
    geocoded = geo.geocode(QueryText="Space Needle, Seattle, WA, USA", MaxResults=1)
    items = geocoded.get("ResultItems", [])
    assert items, "expected a geocode result to seed the concurrent GetPlace calls"
    place_id = items[0]["PlaceId"]

    def _fetch():
        resp = geo.get_place(PlaceId=place_id)
        return resp["Title"], tuple(resp["Position"])

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: _fetch(), range(8)))

    titles = {r[0] for r in results}
    positions = {r[1] for r in results}
    assert len(titles) == 1, f"concurrent GetPlace calls returned different titles: {titles}"
    assert len(positions) == 1, f"concurrent GetPlace calls returned different positions: {positions}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
