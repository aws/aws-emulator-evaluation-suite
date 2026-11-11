"""create-procurement-portal-preference-pending-verification."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-procurement-portal-preference-pending-verification"
GROUP = "lifecycle"
SERVICES = ["invoicing"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:invoicing-procurement-portal")
def run(ctx) -> None:
    """An SAP_BUSINESS_NETWORK preference starts PENDING_VERIFICATION at Version 1; a
    duplicate fails with ConflictException and its exact message; after delete it is
    created again, and Put moves it to Version 2."""
    invoicing = ctx.client("invoicing")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    buyer_id = _valid_sap_buyer_identifier()
    supplier_id = _VALID_SAP_SUPPLIER_IDENTIFIER

    _clear_portal_preference(ctx, "SAP_BUSINESS_NETWORK")
    arn = _create_preference(ctx, "SAP_BUSINESS_NETWORK", buyer_id, supplier_id)

    got = invoicing.get_procurement_portal_preference(
        ProcurementPortalPreferenceArn=arn
    )["ProcurementPortalPreference"]

    assert got["AwsAccountId"] == account_id
    assert got["ProcurementPortalName"] == "SAP_BUSINESS_NETWORK"
    assert got["BuyerDomain"] == "NetworkID"
    assert got["BuyerIdentifier"] == buyer_id
    assert got["SupplierDomain"] == "NetworkID"
    assert got["SupplierIdentifier"] == supplier_id
    assert got["EinvoiceDeliveryPreferenceStatus"] == "PENDING_VERIFICATION"
    assert got["PurchaseOrderRetrievalPreferenceStatus"] == "PENDING_VERIFICATION"
    assert got["Version"] == 1

    # Overly-permissive check: a second SAP_BUSINESS_NETWORK preference while
    # this one exists must be rejected with ConflictException, not silently
    # accepted or overwritten. Reuses the same buyer_id/supplier_id as the
    # original: an earlier attempt with a *different* BuyerIdentifier was
    # observed to succeed, meaning the account is not restricted to a single
    # SAP_BUSINESS_NETWORK preference overall -- the singleton is scoped to
    # (account, portal name, buyer identifier, supplier identifier).
    dup_err = _poll_until_conflict_rejected(
        lambda: invoicing.create_procurement_portal_preference(
            ProcurementPortalName="SAP_BUSINESS_NETWORK",
            BuyerDomain="NetworkID",
            BuyerIdentifier=buyer_id,
            SupplierDomain="NetworkID",
            SupplierIdentifier=supplier_id,
            EinvoiceDeliveryEnabled=False,
            PurchaseOrderRetrievalEnabled=True,
            Contacts=[{"Name": "Second Contact", "Email": "sim2real-second@example.com"}],
        ),
        ctx,
    )
    assert dup_err["Code"] == "ConflictException", f"expected ConflictException, got {dup_err['Code']!r}"
    expected_conflict_message = (
        "There is a procurement portal preference already existed with same portal identifiers"
    )
    assert dup_err["Message"] == expected_conflict_message, (
        f"expected message {expected_conflict_message!r}, got {dup_err['Message']!r}"
    )
    unaffected = invoicing.get_procurement_portal_preference(
        ProcurementPortalPreferenceArn=arn
    )["ProcurementPortalPreference"]
    assert unaffected["Version"] == 1
    matching = [
        p
        for p in invoicing.list_procurement_portal_preferences(MaxResults=100)["ProcurementPortalPreferences"]
        if p["ProcurementPortalName"] == "SAP_BUSINESS_NETWORK"
    ]
    assert len(matching) == 1, f"exactly one SAP_BUSINESS_NETWORK preference expected, found {len(matching)}"

    # Restore: the rejection above was caused by the existing preference, not a
    # broad outage of CreateProcurementPortalPreference -- clear that specific
    # conflict and prove the identical call now succeeds.
    _safe_delete_preference(ctx, arn)
    gone_err = _client_error(
        lambda: invoicing.get_procurement_portal_preference(ProcurementPortalPreferenceArn=arn)
    )
    assert gone_err["Code"] == "ResourceNotFoundException", (
        f"expected the cleared preference to read as gone, got {gone_err['Code']!r}"
    )
    expected_gone_message = f"Procurement portal preference with arn {arn} does not exist"
    assert gone_err["Message"] == expected_gone_message, (
        f"expected message {expected_gone_message!r}, got {gone_err['Message']!r}"
    )
    arn = _create_preference(ctx, "SAP_BUSINESS_NETWORK", buyer_id, supplier_id)
    restored = invoicing.get_procurement_portal_preference(
        ProcurementPortalPreferenceArn=arn
    )["ProcurementPortalPreference"]
    assert restored["Version"] == 1, (
        f"identical create after clearing the conflict should start a fresh Version 1, got {restored['Version']!r}"
    )

    # State check: Put fully replaces the mutable configuration and bumps Version.
    invoicing.put_procurement_portal_preference(
        ProcurementPortalPreferenceArn=arn,
        EinvoiceDeliveryEnabled=False,
        PurchaseOrderRetrievalEnabled=False,
        Contacts=[{"Name": "Updated Contact", "Email": "sim2real-updated@example.com"}],
    )
    after = invoicing.get_procurement_portal_preference(
        ProcurementPortalPreferenceArn=arn
    )["ProcurementPortalPreference"]
    assert after["PurchaseOrderRetrievalEnabled"] is False
    assert after["Contacts"] == [{"Name": "Updated Contact", "Email": "sim2real-updated@example.com"}]
    assert after["Version"] == 2


def _clear_portal_preference(ctx, portal_name: str) -> None:
    """Remove any pre-existing preference for portal_name (e.g. leftover from
    a prior interrupted run), since an account may hold at most one per
    portal name and this check must not depend on ambient state."""
    invoicing = ctx.client("invoicing")
    for pref in invoicing.list_procurement_portal_preferences(MaxResults=100)["ProcurementPortalPreferences"]:
        if pref["ProcurementPortalName"] == portal_name:
            _safe_delete_preference(ctx, pref["ProcurementPortalPreferenceArn"])


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a
    target accepting input real AWS refuses must not read as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until_conflict_rejected(fn, ctx, attempts: int = 5, delay_s: float = 2.0):
    """Retry a duplicate-create attempt until it is rejected, or a fixed budget
    is exhausted; return the rejection's botocore Error dict. If it
    unexpectedly *succeeds* (a lagging conflict check let a duplicate
    through), clean up the accidental duplicate so it doesn't leak, then
    retry. A duplicate that is accepted on every attempt raises."""
    import time

    from botocore.exceptions import ClientError

    for i in range(attempts):
        try:
            resp = fn()
        except ClientError as err:
            return err.response["Error"]
        # Unexpectedly succeeded: clean up the accidental duplicate and retry.
        _safe_delete_preference(ctx, resp["ProcurementPortalPreferenceArn"])
        if i < attempts - 1:
            time.sleep(delay_s)
    raise AssertionError(
        f"a duplicate SAP_BUSINESS_NETWORK preference was accepted on all {attempts} attempts"
    )


# SAP Business Network requires the SupplierIdentifier to be one of this AWS
# account's own registered ANIDs (the service's ValidationException lists the
# "Available values"; it is not user-choosable).
_VALID_SAP_SUPPLIER_IDENTIFIER = "AN01010639538"


def _valid_sap_buyer_identifier() -> str:
    import random

    # SAP Business Network buyer identifiers must be "AN" followed by 11-12
    # digits; the buyer side (unlike the supplier side) is not restricted to
    # a fixed allow-list.
    return "AN" + "".join(str(random.randint(0, 9)) for _ in range(11))


def _create_preference(ctx, portal_name: str, buyer_id: str, supplier_id: str) -> str:
    import time

    from botocore.exceptions import ClientError

    invoicing = ctx.client("invoicing")
    attempts = 5
    last_err = None
    for i in range(attempts):
        try:
            arn = invoicing.create_procurement_portal_preference(
                ProcurementPortalName=portal_name,
                BuyerDomain="NetworkID",
                BuyerIdentifier=buyer_id,
                SupplierDomain="NetworkID",
                SupplierIdentifier=supplier_id,
                EinvoiceDeliveryEnabled=True,
                EinvoiceDeliveryPreference={
                    "ConnectionTestingMethod": "PROD_ENV_DOLLAR_TEST",
                    "EinvoiceDeliveryActivationDate": time.time(),
                    "EinvoiceDeliveryDocumentTypes": ["AWS_CLOUD_INVOICE"],
                    "Protocol": "CXML",
                    "PurchaseOrderDataSources": [
                        {
                            "EinvoiceDeliveryDocumentType": "AWS_CLOUD_INVOICE",
                            "PurchaseOrderDataSourceType": "PURCHASE_ORDER_NOT_REQUIRED",
                        }
                    ],
                },
                PurchaseOrderRetrievalEnabled=True,
                Contacts=[{"Name": "Sim2Real Test Contact", "Email": "sim2real-test@example.com"}],
                ResourceTags=[
                    {"Key": "sim2real-env", "Value": "behavioral"},
                    {"Key": "sim2real-owner", "Value": "invoicing-suite"},
                ],
            )["ProcurementPortalPreferenceArn"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "AccessDeniedException":
                raise AssertionError(
                    "caller lacks permission to create a procurement portal preference "
                    "(preview feature may not be enabled/permitted for this account)"
                ) from err
            if code == "ConflictException" and i < attempts - 1:
                # A leftover preference the initial _clear_portal_preference call
                # raced with (eventual consistency) -- clear again and retry.
                last_err = err
                time.sleep(2.0)
                _clear_portal_preference(ctx, portal_name)
                continue
            raise
        else:
            ctx.on_cleanup(lambda arn=arn: _safe_delete_preference(ctx, arn))
            return arn
    raise last_err


def _safe_delete_preference(ctx, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ctx.client("invoicing").delete_procurement_portal_preference(
            ProcurementPortalPreferenceArn=arn
        )
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


