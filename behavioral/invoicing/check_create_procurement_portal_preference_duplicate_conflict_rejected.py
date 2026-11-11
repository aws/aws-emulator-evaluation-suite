"""create-procurement-portal-preference-duplicate-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-procurement-portal-preference-duplicate-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["invoicing"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:invoicing-procurement-portal")
def run(ctx) -> None:
    """CreateProcurementPortalPreference with an unsupported ProcurementPortalName fails
    with ValidationException and its exact message, and a valid portal with a whitespace
    BuyerIdentifier fails with a different exact ValidationException message."""
    invoicing = ctx.client("invoicing")

    bad_portal_err = _error(
        lambda: invoicing.create_procurement_portal_preference(
            ProcurementPortalName="NOT_A_REAL_PORTAL",
            BuyerDomain="NetworkID",
            BuyerIdentifier="AN01234567890",
            SupplierDomain="NetworkID",
            SupplierIdentifier="AN01234567890",
            EinvoiceDeliveryEnabled=False,
            PurchaseOrderRetrievalEnabled=True,
            Contacts=[{"Name": "Bad Portal Contact", "Email": "sim2real-badportal@example.com"}],
        )
    )
    assert bad_portal_err["Code"] == "ValidationException", (
        f"expected ValidationException for an unsupported ProcurementPortalName, "
        f"got {bad_portal_err['Code']!r}"
    )
    expected_portal_message = (
        "1 validation error detected: Value at 'procurementPortalName' failed to satisfy constraint: "
        "Member must satisfy enum value set: [ZIP, SAP_BUSINESS_NETWORK, JAGGAER, COUPA]"
    )
    assert bad_portal_err["Message"] == expected_portal_message, (
        f"expected message {expected_portal_message!r}, got {bad_portal_err['Message']!r}"
    )

    # Positive control: a request that is valid on ProcurementPortalName but
    # broken on an unrelated field must draw a *different* ValidationException
    # message. Without this, "rejects NOT_A_REAL_PORTAL" is indistinguishable
    # from "rejects every CreateProcurementPortalPreference call".
    bad_identifier_err = _error(
        lambda: invoicing.create_procurement_portal_preference(
            ProcurementPortalName="COUPA",
            BuyerDomain="NetworkID",
            BuyerIdentifier="bad identifier with space",
            SupplierDomain="NetworkID",
            SupplierIdentifier="AN01234567890",
            EinvoiceDeliveryEnabled=False,
            PurchaseOrderRetrievalEnabled=True,
            Contacts=[{"Name": "Bad Identifier Contact", "Email": "sim2real-badid@example.com"}],
        )
    )
    assert bad_identifier_err["Code"] == "ValidationException", (
        f"expected ValidationException for a malformed BuyerIdentifier, "
        f"got {bad_identifier_err['Code']!r}"
    )
    expected_identifier_message = (
        "1 validation error detected: Value at 'buyerIdentifier' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: \\S+"
    )
    assert bad_identifier_err["Message"] == expected_identifier_message, (
        f"expected message {expected_identifier_message!r}, got {bad_identifier_err['Message']!r}"
    )
    assert bad_identifier_err["Message"] != bad_portal_err["Message"], (
        "the enum-value rejection and the malformed-identifier rejection carried "
        f"the identical message {bad_portal_err['Message']!r} -- the service "
        "should be validating fields independently, not returning one generic "
        "ValidationException regardless of what's wrong with the request"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a
    target accepting input real AWS refuses must not read as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


