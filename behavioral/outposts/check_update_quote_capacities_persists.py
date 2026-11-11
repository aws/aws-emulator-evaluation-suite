"""update-quote-capacities-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-quote-capacities-persists"
GROUP = "quotes"
SERVICES = ["outposts"]
_UNIT = "c5.24xlarge"  # large-instance: a quote prices Outposts capacity and launches nothing
_UPDATED_UNIT = "m5.24xlarge"  # large-instance: a quote prices Outposts capacity and launches nothing


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateQuote replaces RequestedCapacities on a CREATED quote and GetQuote reflects the change."""
    outposts = ctx.client("outposts")
    quote_id = outposts.create_quote(
        CountryCode="US",
        RequestedCapacities=[{"QuoteCapacityType": "EC2", "Unit": _UNIT, "Quantity": 4.0}],
    )["Quote"]["QuoteId"]
    ctx.on_cleanup(lambda: outposts.delete_quote(QuoteIdentifier=quote_id))

    outposts.update_quote(
        QuoteIdentifier=quote_id,
        RequestedCapacities=[{"QuoteCapacityType": "EC2", "Unit": _UPDATED_UNIT, "Quantity": 4.0}],
    )

    got = outposts.get_quote(QuoteIdentifier=quote_id)["Quote"]
    assert got["QuoteStatus"] == "CREATED", f"expected CREATED, got {got['QuoteStatus']}"
    capacities = got["RequestedCapacities"]
    assert len(capacities) == 1, f"expected UpdateQuote to replace capacities, got {capacities}"
    assert capacities[0]["Unit"] == _UPDATED_UNIT, f"expected {_UPDATED_UNIT}, got {capacities[0]['Unit']}"
    assert capacities[0]["Quantity"] == 4.0, f"expected 4.0, got {capacities[0]['Quantity']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
