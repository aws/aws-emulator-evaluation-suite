"""search-text-finds-known-landmark."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-text-finds-known-landmark"
GROUP = "search"
SERVICES = ["geo-places"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SearchText for a globally unique landmark name returns it at its real coordinates."""
    geo = ctx.client("geo-places")
    resp = geo.search_text(
        QueryText="Eiffel Tower",
        BiasPosition=[2.2945, 48.8584],  # exactly one of BiasPosition/Filter is required
        MaxResults=5,
    )
    items = resp.get("ResultItems", [])
    assert items, "expected SearchText to find results for 'Eiffel Tower'"

    matches = [i for i in items if "eiffel tower" in i["Title"].lower()]
    assert matches, f"no result titled 'Eiffel Tower' among {[i['Title'] for i in items]}"
    # Eiffel Tower: 48.8584 N, 2.2945 E. More than one result can carry "Eiffel Tower" in its
    # title (a nearby hotel, a tour operator) -- take the one nearest the real landmark rather
    # than trusting result order, so the check does not silently start grading a neighbor's name.
    target_lng, target_lat = 2.2945, 48.8584
    best = min(
        matches,
        key=lambda i: (i["Position"][0] - target_lng) ** 2 + (i["Position"][1] - target_lat) ** 2,
    )
    lng, lat = best["Position"]
    assert abs(lng - target_lng) <= 0.01, f"{best['Title']!r} longitude {lng} not near the Eiffel Tower"
    assert abs(lat - target_lat) <= 0.01, f"{best['Title']!r} latitude {lat} not near the Eiffel Tower"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
