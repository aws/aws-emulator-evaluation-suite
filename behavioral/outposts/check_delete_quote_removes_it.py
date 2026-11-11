"""delete-quote-removes-it."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-quote-removes-it"
GROUP = "state"
SERVICES = ["outposts"]
_UNIT = "c5.24xlarge"  # large-instance: a quote prices Outposts capacity and launches nothing


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteQuote removes the quote so a subsequent GetQuote raises NotFoundException,
    and the dead QuoteId is not just unreadable but unusable: a second DeleteQuote against
    the same identifier also fails with the same specific error rather than no-opping."""
    outposts = ctx.client("outposts")
    quote_id = outposts.create_quote(
        CountryCode="US",
        RequestedCapacities=[{"QuoteCapacityType": "EC2", "Unit": _UNIT, "Quantity": 4.0}],
    )["Quote"]["QuoteId"]
    ctx.on_cleanup(lambda: _delete_ignoring_not_found(lambda: outposts.delete_quote(QuoteIdentifier=quote_id)))

    outposts.delete_quote(QuoteIdentifier=quote_id)

    expected = f"Could not find Quote with identifier {quote_id}"
    code, message = _error(lambda: outposts.get_quote(QuoteIdentifier=quote_id))
    assert code == "NotFoundException", f"expected NotFoundException reading a deleted quote, got {code!r}"
    assert message == expected, f"unexpected GetQuote message for a deleted quote: {message!r}"

    code, message = _error(lambda: outposts.delete_quote(QuoteIdentifier=quote_id))
    assert code == "NotFoundException", (
        f"expected a second DeleteQuote on the dead id to also fail with NotFoundException, got {code!r}"
    )
    assert message == expected, f"unexpected second DeleteQuote message: {message!r}"


def _error(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_ignoring_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
