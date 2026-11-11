"""create-procurement-portal-preference-invalid-identifier-pattern-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-procurement-portal-preference-invalid-identifier-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["invoicing"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:invoicing-procurement-portal")
def run(ctx) -> None:
    """CreateProcurementPortalPreference with a whitespace BuyerIdentifier fails with
    ValidationException and its exact message and creates no preference, while the same
    call with a well-formed identifier succeeds."""
    invoicing = ctx.client("invoicing")
    supplier_id = ctx.unique_name("sim2real-supplier-")

    _clear_portal_preference(ctx, "COUPA")

    good_arn = invoicing.create_procurement_portal_preference(
        ProcurementPortalName="COUPA",
        BuyerDomain="NetworkID",
        BuyerIdentifier=ctx.unique_name("sim2real-buyer-"),
        SupplierDomain="NetworkID",
        SupplierIdentifier=supplier_id,
        EinvoiceDeliveryEnabled=False,
        PurchaseOrderRetrievalEnabled=True,
        ProcurementPortalSharedSecret="sim2real-shared-secret-value",
        ProcurementPortalInstanceEndpoint="https://sim2real-behav.example.com/procurement-portal",
        Contacts=[{"Name": "Good Contact", "Email": "sim2real-good@example.com"}],
    )["ProcurementPortalPreferenceArn"]
    ctx.on_cleanup(lambda: _safe_delete_preference(ctx, good_arn))
    _safe_delete_preference(ctx, good_arn)

    error = _client_error(
        ctx,
        lambda: invoicing.create_procurement_portal_preference(
            ProcurementPortalName="COUPA",
            BuyerDomain="NetworkID",
            BuyerIdentifier="bad identifier with space",
            SupplierDomain="NetworkID",
            SupplierIdentifier=supplier_id,
            EinvoiceDeliveryEnabled=False,
            PurchaseOrderRetrievalEnabled=True,
            ProcurementPortalSharedSecret="sim2real-shared-secret-value",
            ProcurementPortalInstanceEndpoint="https://sim2real-behav.example.com/procurement-portal",
            Contacts=[{"Name": "Bad Contact", "Email": "sim2real-bad@example.com"}],
        ),
    )
    assert error.get("Code") == "ValidationException", (
        f"a BuyerIdentifier containing whitespace was rejected with "
        f"{error.get('Code')!r}, expected 'ValidationException'"
    )
    expected_message = (
        "1 validation error detected: Value at 'buyerIdentifier' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: \\S+"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    matching = [
        p
        for p in invoicing.list_procurement_portal_preferences(MaxResults=100)["ProcurementPortalPreferences"]
        if p["ProcurementPortalName"] == "COUPA"
    ]
    assert len(matching) == 0, (
        f"the rejected create must not leave a COUPA preference behind, found {len(matching)}"
    )


def _clear_portal_preference(ctx, portal_name: str) -> None:
    """Remove any pre-existing preference for portal_name (e.g. leftover from
    a prior interrupted run), since an account may hold at most one per
    portal name and this check must not depend on ambient state."""
    invoicing = ctx.client("invoicing")
    for pref in invoicing.list_procurement_portal_preferences(MaxResults=100)["ProcurementPortalPreferences"]:
        if pref["ProcurementPortalName"] == portal_name:
            _safe_delete_preference(ctx, pref["ProcurementPortalPreferenceArn"])


def _safe_delete_preference(ctx, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ctx.client("invoicing").delete_procurement_portal_preference(
            ProcurementPortalPreferenceArn=arn
        )
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _client_error(ctx, fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises (after cleaning up
    the leaked preference), because an over-permissive target accepting a malformed identifier is
    the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    leaked_arn = result["ProcurementPortalPreferenceArn"]
    _safe_delete_preference(ctx, leaked_arn)
    raise AssertionError(
        f"real AWS rejects a BuyerIdentifier containing whitespace, but the call "
        f"SUCCEEDED and created {leaked_arn!r} (cleaned up)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


