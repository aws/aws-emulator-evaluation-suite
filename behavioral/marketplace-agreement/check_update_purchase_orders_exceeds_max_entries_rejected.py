"""update-purchase-orders-exceeds-max-entries-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-purchase-orders-exceeds-max-entries-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-agreement"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdatePurchaseOrders refuses more than 86 purchaseOrders entries with ValidationException "Provided
    purchase orders is invalid.", while 86 entries pass that check and get "This action is not supported."
    """
    # marketplace-agreement answers only in us-east-1, so the client pins that region.
    mpa = ctx.client("marketplace-agreement", region="us-east-1")

    def _entry(i):
        return {
            "agreementId": ctx.unique_name(f"sim2real-agreement-{i}-"),
            "chargeId": ctx.unique_name(f"sim2real-charge-{i}-"),
            "chargeRevision": 1,
        }

    too_many = [_entry(i) for i in range(87)]
    bad_code, bad_message = _error_code(lambda: mpa.update_purchase_orders(purchaseOrders=too_many))
    assert bad_code == "ValidationException", f"expected ValidationException, got {bad_code!r}"
    assert bad_message == "Provided purchase orders is invalid.", f"unexpected message: {bad_message!r}"

    at_max = [_entry(i) for i in range(86)]
    control_code, control_message = _error_code(
        lambda: mpa.update_purchase_orders(purchaseOrders=at_max)
    )
    # The size-compliant call clears the 86-entry cap and is refused for a different reason
    # (the account is not provisioned for purchase-order association), so the cap, not the
    # entries' content, is what the bad case caught.
    assert control_code == "ValidationException", f"expected ValidationException, got {control_code!r}"
    assert control_message == "This action is not supported.", (
        f"unexpected message: {control_message!r}"
    )


def _error_code(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
