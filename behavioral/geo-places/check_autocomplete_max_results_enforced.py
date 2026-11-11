"""autocomplete-max-results-enforced."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "autocomplete-max-results-enforced"
GROUP = "search"
SERVICES = ["geo-places"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Autocomplete with MaxResults 1 returns exactly one suggestion for a query that returns several with a
    higher MaxResults.
    """
    geo = ctx.client("geo-places")
    bias_position = [-122.3493, 47.6205]  # downtown Seattle, dense with coffee shops

    control = geo.autocomplete(
        QueryText="Coffee",
        BiasPosition=bias_position,
        MaxResults=5,
    )
    control_items = control.get("ResultItems", [])
    assert len(control_items) > 1, (
        f"expected more than 1 unclamped coffee suggestion near downtown Seattle "
        f"to prove MaxResults=1 has something to truncate, got {len(control_items)}"
    )

    resp = geo.autocomplete(
        QueryText="Coffee",
        BiasPosition=bias_position,
        MaxResults=1,
    )
    items = resp.get("ResultItems", [])
    assert len(items) == 1, f"expected exactly 1 result when MaxResults=1, got {len(items)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
