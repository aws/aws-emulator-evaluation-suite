"""create-quote-returns-created-status."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-quote-returns-created-status"
GROUP = "quotes"
SERVICES = ["outposts"]
_UNIT = "c5.24xlarge"  # large-instance: a quote prices Outposts capacity and launches nothing


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateQuote returns a quote in CREATED status echoing the requested capacity/country,
    and an independent GetQuote confirms the same values were durably stored, not just echoed."""
    outposts = ctx.client("outposts")
    resp = outposts.create_quote(
        CountryCode="US",
        RequestedCapacities=[{"QuoteCapacityType": "EC2", "Unit": _UNIT, "Quantity": 4.0}],
    )
    quote = resp["Quote"]
    quote_id = quote["QuoteId"]
    ctx.on_cleanup(lambda: outposts.delete_quote(QuoteIdentifier=quote_id))

    assert quote["QuoteStatus"] == "CREATED", f"CreateQuote status: expected CREATED, got {quote['QuoteStatus']!r}"
    assert quote["CountryCode"] == "US", f"CreateQuote country: expected US, got {quote['CountryCode']!r}"
    assert quote["RequestedCapacities"][0]["QuoteCapacityType"] == "EC2", (
        f"CreateQuote capacity type: expected EC2, got {quote['RequestedCapacities']!r}"
    )
    assert quote["RequestedCapacities"][0]["Unit"] == _UNIT, (
        f"CreateQuote capacity unit: expected {_UNIT}, got {quote['RequestedCapacities']!r}"
    )

    fetched = outposts.get_quote(QuoteIdentifier=quote_id)["Quote"]
    assert fetched["QuoteId"] == quote_id, f"GetQuote id: expected {quote_id!r}, got {fetched['QuoteId']!r}"
    assert fetched["QuoteStatus"] == "CREATED", f"GetQuote status: expected CREATED, got {fetched['QuoteStatus']!r}"
    assert fetched["CountryCode"] == "US", f"GetQuote country: expected US, got {fetched['CountryCode']!r}"
    assert fetched["RequestedCapacities"][0]["QuoteCapacityType"] == "EC2", (
        f"GetQuote capacity type: expected EC2, got {fetched['RequestedCapacities']!r}"
    )
    assert fetched["RequestedCapacities"][0]["Unit"] == _UNIT, (
        f"GetQuote capacity unit: expected {_UNIT}, got {fetched['RequestedCapacities']!r}"
    )
    assert fetched["RequestedCapacities"][0]["Quantity"] == 4.0, (
        f"GetQuote capacity quantity: expected 4.0, got {fetched['RequestedCapacities']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
