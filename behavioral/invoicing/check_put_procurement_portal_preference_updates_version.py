"""put-procurement-portal-preference-updates-version."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-procurement-portal-preference-updates-version"
GROUP = "overly-permissive"
SERVICES = ["invoicing"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:invoicing-procurement-portal")
def run(ctx) -> None:
    """PutProcurementPortalPreference replaces a real preference's configuration at
    Version 2, while Put or Get on a nonexistent or deleted preference ARN fails with
    ResourceNotFoundException and its exact message."""
    invoicing = ctx.client("invoicing")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    arn = _create_preference(ctx)
    created = invoicing.get_procurement_portal_preference(ProcurementPortalPreferenceArn=arn)[
        "ProcurementPortalPreference"
    ]
    assert created["Version"] == 1, f"expected a fresh preference at Version 1, got {created['Version']}"

    invoicing.put_procurement_portal_preference(
        ProcurementPortalPreferenceArn=arn,
        EinvoiceDeliveryEnabled=False,
        PurchaseOrderRetrievalEnabled=False,
        Contacts=[{"Name": "Updated Contact", "Email": "sim2real-updated@example.com"}],
    )
    updated = invoicing.get_procurement_portal_preference(ProcurementPortalPreferenceArn=arn)[
        "ProcurementPortalPreference"
    ]
    assert updated["PurchaseOrderRetrievalEnabled"] is False, (
        f"expected PurchaseOrderRetrievalEnabled False after Put, got {updated['PurchaseOrderRetrievalEnabled']!r}"
    )
    assert updated["Contacts"] == [{"Name": "Updated Contact", "Email": "sim2real-updated@example.com"}], (
        f"expected Put to fully replace Contacts, got {updated['Contacts']!r}"
    )
    assert updated["Version"] == 2, f"expected Put on a real preference to bump Version to 2, got {updated['Version']}"

    fake_arn = f"arn:aws:invoicing::{account_id}:procurement-portal-preference/sim2real-does-not-exist"
    code, message = _error(
        lambda: invoicing.put_procurement_portal_preference(
            ProcurementPortalPreferenceArn=fake_arn,
            EinvoiceDeliveryEnabled=False,
            PurchaseOrderRetrievalEnabled=False,
            Contacts=[{"Name": "Ghost Contact", "Email": "sim2real-ghost@example.com"}],
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException for a nonexistent ARN, got {code!r}"
    expected = f"Procurement portal preference with arn {fake_arn} does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: a nonexistent ARN must still read as nonexistent afterward.
    get_code, get_message = _error(
        lambda: invoicing.get_procurement_portal_preference(ProcurementPortalPreferenceArn=fake_arn)
    )
    assert get_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a nonexistent ARN, got {get_code!r}"
    )
    expected = f"Procurement portal preference with arn {fake_arn} does not exist"
    assert get_message == expected, f"expected message {expected!r}, got {get_message!r}"

    # Delete this check's own preference inline (not just at teardown) so the
    # dead-id proof below runs on an ARN that genuinely existed, a stronger
    # negative than fake_arn, which never did.
    invoicing.delete_procurement_portal_preference(ProcurementPortalPreferenceArn=arn)
    deleted_get_code, deleted_get_message = _error(
        lambda: invoicing.get_procurement_portal_preference(ProcurementPortalPreferenceArn=arn)
    )
    assert deleted_get_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a deleted preference, got {deleted_get_code!r}"
    )
    expected = f"Procurement portal preference with arn {arn} does not exist"
    assert deleted_get_message == expected, f"expected message {expected!r}, got {deleted_get_message!r}"
    deleted_put_code, deleted_put_message = _error(
        lambda: invoicing.put_procurement_portal_preference(
            ProcurementPortalPreferenceArn=arn,
            EinvoiceDeliveryEnabled=False,
            PurchaseOrderRetrievalEnabled=False,
            Contacts=[{"Name": "Zombie Contact", "Email": "sim2real-zombie@example.com"}],
        )
    )
    assert deleted_put_code == "ResourceNotFoundException", (
        f"expected Put on a deleted preference to be rejected, got {deleted_put_code!r}"
    )
    expected = f"Procurement portal preference with arn {arn} does not exist"
    assert deleted_put_message == expected, f"expected message {expected!r}, got {deleted_put_message!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"].get("Code"), err.response["Error"].get("Message")
    raise AssertionError("expected a ClientError, call unexpectedly succeeded")


def _create_preference(ctx) -> str:
    import time

    from botocore.exceptions import ClientError

    invoicing = ctx.client("invoicing")
    buyer_id = _valid_sap_buyer_identifier()
    attempts = 5
    last_err = None
    for i in range(attempts):
        try:
            arn = invoicing.create_procurement_portal_preference(
                ProcurementPortalName="SAP_BUSINESS_NETWORK",
                BuyerDomain="NetworkID",
                BuyerIdentifier=buyer_id,
                SupplierDomain="NetworkID",
                SupplierIdentifier=_VALID_SAP_SUPPLIER_IDENTIFIER,
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
            )["ProcurementPortalPreferenceArn"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "AccessDeniedException":
                raise AssertionError(
                    "caller lacks permission to create a procurement portal preference "
                    "(preview feature may not be enabled/permitted for this account)"
                ) from err
            if code == "ConflictException" and i < attempts - 1:
                # An extremely unlucky BuyerIdentifier collision -- retry with a new one.
                buyer_id = _valid_sap_buyer_identifier()
                last_err = err
                time.sleep(2.0)
                continue
            raise
        else:
            ctx.on_cleanup(lambda arn=arn: _safe_delete_preference(ctx, arn))
            return arn
    raise last_err


def _safe_delete_preference(ctx, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ctx.client("invoicing").delete_procurement_portal_preference(ProcurementPortalPreferenceArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


# SAP Business Network requires the SupplierIdentifier to be one of AWS's own
# supplier ANIDs: a fixed, service-published list (the ValidationException's
# "Available values"), identical in every account, not a resource to create.
_VALID_SAP_SUPPLIER_IDENTIFIER = "AN01010639538"


def _valid_sap_buyer_identifier() -> str:
    import random

    # SAP Business Network buyer identifiers must be "AN" followed by 11-12
    # digits; the buyer side (unlike the supplier side) is not restricted to
    # a fixed allow-list.
    return "AN" + "".join(str(random.randint(0, 9)) for _ in range(11))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


