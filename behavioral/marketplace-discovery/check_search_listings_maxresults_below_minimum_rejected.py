"""search-listings-maxresults-below-minimum-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "search-listings-maxresults-below-minimum-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-discovery"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SearchListings rejects maxResults=0 (documented minimum 1) server-side with ValidationException
    and the exact range message, while maxResults=1 succeeds; client-side validation is off so the value
    reaches the service."""
    md = ctx.client("marketplace-discovery")

    # Positive control: the minimum in-range value still succeeds.
    resp = md.search_listings(maxResults=1)
    assert len(resp["listingSummaries"]) <= 1, resp["listingSummaries"]
    assert resp["totalResults"] >= len(resp["listingSummaries"]), (
        resp["totalResults"],
        resp["listingSummaries"],
    )

    unvalidated = ctx.client("marketplace-discovery", config=Config(parameter_validation=False))
    code, message = _error(lambda: unvalidated.search_listings(maxResults=0))
    assert code == "ValidationException", code
    assert message == (
        "1 validation error detected: Value '0' at 'maxResults' failed to satisfy "
        "constraint: Member must have value greater than or equal to 1"
    ), message


def _error(fn):
    """(code, message) of the ClientError fn raises; a success is an AssertionError."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
