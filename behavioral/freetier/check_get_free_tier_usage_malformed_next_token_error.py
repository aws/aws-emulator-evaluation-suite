"""get-free-tier-usage-malformed-next-token-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-free-tier-usage-malformed-next-token-error"
GROUP = "error-semantics"
SERVICES = ["freetier"]


def _error(fn):
    """Call fn() and return its ClientError's Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetFreeTierUsage rejects an opaque, non-decodable nextToken with ValidationException.

    Positive control first: a plain call with no token must succeed, so the rejection below
    is proven specific to the malformed token rather than the account being denied outright.
    """
    freetier = ctx.client("freetier")

    before = freetier.get_free_tier_usage(maxResults=5)
    assert isinstance(before.get("freeTierUsages"), list), before

    error = _error(lambda: freetier.get_free_tier_usage(nextToken="not-a-real-pagination-token"))
    assert error["Code"] == "ValidationException", error
    assert error["Message"] == "[Message = The next token is invalid.]", error

    # effect absent + control: the rejected call left ordinary pagination unaffected
    after = freetier.get_free_tier_usage(maxResults=5)
    assert len(after.get("freeTierUsages", [])) == len(before.get("freeTierUsages", [])), (before, after)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
