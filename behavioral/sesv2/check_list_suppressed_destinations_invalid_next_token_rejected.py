"""list-suppressed-destinations-invalid-next-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-suppressed-destinations-invalid-next-token-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListSuppressedDestinations with a malformed/foreign pagination token is rejected
    with InvalidNextTokenException, while the same call without a token still succeeds."""
    sesv2 = ctx.client("sesv2")

    err = _error(
        lambda: sesv2.list_suppressed_destinations(NextToken="not-a-real-pagination-token")
    )
    assert err == ("InvalidNextTokenException", "Token is invalid."), (
        f"expected InvalidNextTokenException, got {err!r}"
    )

    # positive control: an unpaginated call still succeeds
    resp = sesv2.list_suppressed_destinations()
    assert "SuppressedDestinationSummaries" in resp, (
        f"expected SuppressedDestinationSummaries in positive-control response, got keys={list(resp)!r}"
    )


def _error(fn):
    """Return the rejected call's (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
