"""describe-inbound-connections-malformed-filter-and-pagination-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-inbound-connections-malformed-filter-and-pagination-token-rejected"
GROUP = "connections"
SERVICES = ["opensearch"]


def _error(fn) -> "tuple[str, str]":
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success
    raises, because accepting a call AWS refuses must not read as an ordinary code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeInboundConnections rejects a pagination token it never issued with
    InvalidPaginationTokenException, and a filter name outside the documented set with
    ValidationException, each with its exact message."""
    osc = ctx.client("opensearch")

    bogus_token = ctx.unique_name("sim2real-behav-token-")
    token_refusal = _error(lambda: osc.describe_inbound_connections(NextToken=bogus_token))
    assert token_refusal == ("InvalidPaginationTokenException", "Pagination token provided is invalid"), (
        f"expected InvalidPaginationTokenException with AWS's exact message for an unissued "
        f"pagination token, got {token_refusal!r}"
    )

    bogus_filter_name = "not a real filter"
    filter_refusal = _error(
        lambda: osc.describe_inbound_connections(
            Filters=[{"Name": bogus_filter_name, "Values": ["x"]}]
        )
    )
    expected_filter_message = (
        f"1 validation error detected: Value '{bogus_filter_name}' at 'filters.1.member.name' "
        f"failed to satisfy constraint: Member must satisfy regular expression pattern: "
        f"[a-zA-Z0-9\\-\\_\\.]+"
    )
    assert filter_refusal == ("ValidationException", expected_filter_message), (
        f"expected ValidationException with AWS's exact message for an unsupported filter name, "
        f"got {filter_refusal!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
