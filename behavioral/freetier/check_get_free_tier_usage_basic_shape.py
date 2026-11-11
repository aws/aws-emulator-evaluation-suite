"""get-free-tier-usage-basic-shape."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-free-tier-usage-basic-shape"
GROUP = "state"
SERVICES = ["freetier"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetFreeTierUsage returns FreeTierUsage records with well-typed, non-negative numeric fields."""
    freetier = ctx.client("freetier")
    resp = freetier.get_free_tier_usage(maxResults=10)

    usages = resp["freeTierUsages"]
    assert isinstance(usages, list), f"expected freeTierUsages to be a list, got {type(usages)!r}"
    for item in usages:
        service = item["service"]
        unit = item["unit"]
        actual = item["actualUsageAmount"]
        forecast = item["forecastedUsageAmount"]
        limit = item["limit"]
        assert isinstance(service, str), f"expected service to be a str, got {service!r}"
        assert isinstance(unit, str), f"expected unit to be a str, got {unit!r}"
        assert isinstance(actual, (int, float)) and actual >= 0, (
            f"expected actualUsageAmount >= 0, got {actual!r}"
        )
        assert isinstance(forecast, (int, float)) and forecast >= 0, (
            f"expected forecastedUsageAmount >= 0, got {forecast!r}"
        )
        assert isinstance(limit, (int, float)) and limit >= 0, f"expected limit >= 0, got {limit!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
