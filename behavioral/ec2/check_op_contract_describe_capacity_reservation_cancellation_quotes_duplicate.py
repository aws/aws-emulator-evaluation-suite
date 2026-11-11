"""op-contract-describe-capacity-reservation-cancellation-quotes-duplicate."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-capacity-reservation-cancellation-quotes-duplicate"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeCapacityReservationCancellationQuotes lists prior quotes and enforces DryRun."""
    ec2 = ctx.client("ec2")
    _require_op(ec2, "describe_capacity_reservation_cancellation_quotes")

    response = ec2.describe_capacity_reservation_cancellation_quotes()
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected HTTP 200, got {response['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    # substantive assertion directly on the response body (confirmed shape: top-level
    # "CapacityReservationCancellationQuotes" list -- see the CLI Output section for
    # describe-capacity-reservation-cancellation-quotes).
    assert "CapacityReservationCancellationQuotes" in response, (
        f"expected CapacityReservationCancellationQuotes in response body: {response!r}"
    )
    quotes = response["CapacityReservationCancellationQuotes"]
    assert isinstance(quotes, list), (
        f"expected CapacityReservationCancellationQuotes to be a list, got {quotes!r}"
    )
    for item in quotes:
        assert isinstance(item, dict), f"cancellation-quote record should be dict-shaped, got {item!r}"
        assert "CapacityReservationCancellationQuoteId" in item or "CapacityReservationId" in item, (
            f"quote record missing CapacityReservationCancellationQuoteId/CapacityReservationId: {item!r}"
        )
    if not quotes:
        assert response.get("NextToken") in (None, ""), (
            "NextToken should be empty/absent when the result set is empty"
        )

    # id-format contract (empirically confirmed against real AWS): the service validates the
    # shape of a CapacityReservationCancellationQuoteId before ever looking it up, so a string
    # that merely LOOKS plausible but does not match the real id format is rejected as malformed
    # rather than silently treated as "not found".
    bogus_id = "cr-cq-0123456789abcdef0"
    code, message = _error(
        lambda: ec2.describe_capacity_reservation_cancellation_quotes(
            CapacityReservationCancellationQuoteIds=[bogus_id]
        )
    )
    assert code == "InvalidCapacityReservationCancellationQuoteId.Malformed", (
        f"expected InvalidCapacityReservationCancellationQuoteId.Malformed, got {code!r}"
    )
    assert message == f"Cancellation Quote Id '{bogus_id}' is malformed.", (
        f"unexpected Malformed message: {message!r}"
    )

    code, message = _error(lambda: ec2.describe_capacity_reservation_cancellation_quotes(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {message!r}"
    )


def _require_op(client: Any, op_name: str) -> None:

    if not hasattr(client, op_name):
        raise AssertionError(f"ec2 client missing operation {op_name!r} (botocore too old)")


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
