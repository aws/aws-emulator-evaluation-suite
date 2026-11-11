"""batch-create-billing-adjustment-request-partial-failure-surfaced."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-create-billing-adjustment-request-partial-failure-surfaced"
GROUP = "batch-semantics"
SERVICES = ["marketplace-agreement"]


@tags("axis:happy-path", "cap:c1", "plane:control")
def run(ctx) -> None:
    """BatchCreateBillingAdjustmentRequest with an entry for a nonexistent agreement succeeds, creates no
    items and reports that entry in errors as RESOURCE_NOT_FOUND_EXCEPTION with its exact message; a
    refused listing of that agreement's requests is ValidationException with its exact message.
    """
    # marketplace-agreement is served only from us-east-1, so every target is addressed there.
    mpa = ctx.client("marketplace-agreement", region="us-east-1")

    bogus_entry = {
        "agreementId": ctx.unique_name("sim2real-no-such-agreement-"),
        "originalInvoiceId": ctx.unique_name("sim2real-no-such-invoice-"),
        "adjustmentAmount": "1.00",
        "currencyCode": "USD",
        "adjustmentReasonCode": "TEST_ENVIRONMENT_CHARGES",
        "clientToken": ctx.unique_name("sim2real-token-"),
    }

    resp = mpa.batch_create_billing_adjustment_request(
        billingAdjustmentRequestEntries=[bogus_entry]
    )

    assert isinstance(resp.get("items", []), list)
    errors = resp.get("errors", [])
    assert len(errors) == 1, f"expected exactly one per-entry error, got {resp!r}"
    assert errors[0]["clientToken"] == bogus_entry["clientToken"], (
        f"error entry must be keyed back to the failing clientToken "
        f"{bogus_entry['clientToken']!r}, got {errors[0]!r}"
    )
    got_entry = (errors[0].get("code"), errors[0].get("message"))
    want_entry = ("RESOURCE_NOT_FOUND_EXCEPTION", "Provided agreement does not exist.")
    assert got_entry == want_entry, (
        f"a nonexistent agreementId must classify as {want_entry!r}, got {got_entry!r}"
    )
    assert len(resp.get("items", [])) == 0, "the failing entry must not also appear as a created item"

    try:
        mpa.list_billing_adjustment_requests(agreementId=bogus_entry["agreementId"])
    except ClientError as e:
        got = (e.response["Error"]["Code"], e.response["Error"].get("Message"))
        want = ("ValidationException", "Provided agreement id is invalid.")
        assert got == want, (
            f"an independent list by the same agreementId the batch call rejected as "
            f"nonexistent must fail with {want!r}, got {got!r}"
        )
    else:
        raise AssertionError(
            "expected ListBillingAdjustmentRequests to independently reject the same "
            "nonexistent agreementId the batch call had already rejected, but it succeeded"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
