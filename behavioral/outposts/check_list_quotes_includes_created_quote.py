"""list-quotes-includes-created-quote."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-quotes-includes-created-quote"
GROUP = "quotes"
SERVICES = ["outposts"]
_UNIT = "c5.24xlarge"  # large-instance: a quote prices Outposts capacity and launches nothing


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created quote's ID appears in the paginated ListQuotes results for the account."""
    outposts = ctx.client("outposts")
    quote_id = outposts.create_quote(
        CountryCode="US",
        RequestedCapacities=[{"QuoteCapacityType": "EC2", "Unit": _UNIT, "Quantity": 4.0}],
    )["Quote"]["QuoteId"]
    ctx.on_cleanup(lambda: outposts.delete_quote(QuoteIdentifier=quote_id))

    found = None
    kwargs: dict = {}
    for _ in range(50):
        resp = outposts.list_quotes(**kwargs)
        for item in resp.get("Quotes", []):
            if item.get("QuoteId") == quote_id:
                found = item
                break
        if found is not None:
            break
        token = resp.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token

    assert found is not None, f"quote {quote_id} not found in ListQuotes"
    assert found["QuoteStatus"] == "CREATED", (
        f"expected QuoteStatus CREATED, got {found['QuoteStatus']!r} for quote {quote_id}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
