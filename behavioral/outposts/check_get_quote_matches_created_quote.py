"""get-quote-matches-created-quote."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-quote-matches-created-quote"
GROUP = "quotes"
SERVICES = ["outposts"]
_UNIT = "c5.24xlarge"  # large-instance: a quote prices Outposts capacity and launches nothing


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetQuote returns the same QuoteId/CountryCode/RequestedCapacities as CreateQuote produced."""
    outposts = ctx.client("outposts")
    created = outposts.create_quote(
        CountryCode="DE",
        RequestedCapacities=[
            {"QuoteCapacityType": "EC2", "Unit": _UNIT, "Quantity": 4.0},
            {"QuoteCapacityType": "EBS", "Unit": "TiB", "Quantity": 2.0},
        ],
        Description="sim2real behavioral quote",
    )["Quote"]
    quote_id = created["QuoteId"]
    ctx.on_cleanup(lambda: outposts.delete_quote(QuoteIdentifier=quote_id))

    got = outposts.get_quote(QuoteIdentifier=quote_id)["Quote"]
    assert got["QuoteId"] == quote_id, f"expected QuoteId {quote_id!r}, got {got['QuoteId']!r}"
    assert got["CountryCode"] == "DE", f"expected CountryCode 'DE', got {got['CountryCode']!r}"
    assert got["QuoteStatus"] == "CREATED", (
        f"expected QuoteStatus 'CREATED', got {got['QuoteStatus']!r}"
    )
    assert got["Description"] == "sim2real behavioral quote", (
        f"expected Description 'sim2real behavioral quote', got {got['Description']!r}"
    )
    capacities_by_type = {c["QuoteCapacityType"]: c for c in got["RequestedCapacities"]}
    assert "EBS" in capacities_by_type, (
        f"expected an EBS capacity in GetQuote response, got types {list(capacities_by_type)}"
    )
    ebs_capacity = capacities_by_type["EBS"]
    assert ebs_capacity["Quantity"] == 2.0, (
        f"expected EBS Quantity 2.0, got {ebs_capacity['Quantity']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
