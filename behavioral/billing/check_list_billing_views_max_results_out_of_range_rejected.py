"""list-billing-views-max-results-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-billing-views-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["billing"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListBillingViews with maxResults=1 succeeds, while maxResults=0 (sent with client-side validation off)
    and maxResults=101 fail server-side with ValidationException carrying the exact 1-100 range messages."""
    from botocore.config import Config

    billing = ctx.client("billing")
    unvalidated = ctx.client("billing", config=Config(parameter_validation=False))

    # positive control: boundary-valid maxResults succeeds
    resp = billing.list_billing_views(maxResults=1)
    assert "billingViews" in resp

    # negative: 0 is below the documented minimum of 1 (server-side rejection,
    # forced onto the wire past the SDK's own client-side range check)
    code_zero, message_zero = _error_code(lambda: unvalidated.list_billing_views(maxResults=0))
    assert code_zero == "ValidationException", code_zero
    assert message_zero == "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: Member must have value greater than or equal to 1", (
        f"expected the exact ValidationException message AWS returns, got {message_zero!r}"
    )

    # negative: 101 is above the documented maximum of 100 (server-side rejection)
    code, message = _error_code(lambda: billing.list_billing_views(maxResults=101))
    assert code == "ValidationException", code
    assert message == "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: Member must have value less than or equal to 100", (
        f"expected the exact ValidationException message AWS returns, got {message!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


