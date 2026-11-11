"""list-billing-adjustment-requests-invalid-date-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-billing-adjustment-requests-invalid-date-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-agreement"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListBillingAdjustmentRequests refuses a maxResults outside [1,50] with ValidationException and its
    exact message, while maxResults=50 returns an items list.
    """
    # marketplace-agreement is served only from us-east-1, so every target is addressed there.
    mpa = ctx.client("marketplace-agreement", region="us-east-1")

    bad = _error_code(lambda: mpa.list_billing_adjustment_requests(maxResults=51))
    want = ("ValidationException", "Provided max results is invalid.")
    assert bad == want, f"expected {want!r}, got {bad!r}"

    # Positive control: the boundary value itself (50) is accepted.
    resp = mpa.list_billing_adjustment_requests(maxResults=50)
    assert isinstance(resp["items"], list), f"expected 'items' to be a list, got {resp['items']!r}"


def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, so a
    target accepting input real AWS refuses never reads as an ordinary code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
