"""list-procurement-portal-preferences-contains-created."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-procurement-portal-preferences-contains-created"
GROUP = "crud"
SERVICES = ["invoicing"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:invoicing-procurement-portal")
def run(ctx) -> None:
    """A created COUPA preference is listed; SendProcurementPortalValidation and a wrong-code
    VerifyProcurementPortalValidation each fail with ValidationException and their exact
    messages, status stays PENDING_VERIFICATION, and Version rises by one on each."""
    invoicing = ctx.client("invoicing")
    buyer_id = ctx.unique_name("sim2real-buyer-")
    supplier_id = ctx.unique_name("sim2real-supplier-")

    _clear_portal_preference(ctx, "COUPA")
    arn = _create_preference(ctx, "COUPA", buyer_id, supplier_id)

    found = None
    next_token = None
    while True:
        kwargs = {"MaxResults": 100}
        if next_token:
            kwargs["NextToken"] = next_token
        page = invoicing.list_procurement_portal_preferences(**kwargs)
        for pref in page["ProcurementPortalPreferences"]:
            if pref["ProcurementPortalPreferenceArn"] == arn:
                found = pref
                break
        next_token = page.get("NextToken")
        if found or not next_token:
            break

    assert found is not None, f"created preference {arn!r} not found in ListProcurementPortalPreferences"
    assert found["ProcurementPortalName"] == "COUPA"
    assert found["BuyerDomain"] == "NetworkID"
    assert found["SupplierDomain"] == "NetworkID"
    assert found["EinvoiceDeliveryEnabled"] is True
    assert found["PurchaseOrderRetrievalEnabled"] is True

    before = invoicing.get_procurement_portal_preference(
        ProcurementPortalPreferenceArn=arn
    )["ProcurementPortalPreference"]
    assert before["EinvoiceDeliveryPreferenceStatus"] == "PENDING_VERIFICATION"
    assert before["PurchaseOrderRetrievalPreferenceStatus"] == "PENDING_VERIFICATION"
    assert before["Version"] == 1

    # SendProcurementPortalValidation actually attempts to deliver a test
    # e-invoice to the configured ProcurementPortalInstanceEndpoint -- ours
    # is a synthetic domain that can never receive it, so the send is
    # deterministically rejected. The
    # message is delivery-shaped rather than a blanket permission denial,
    # which is what distinguishes "this account can use the API but the
    # endpoint is unreachable" from "this account can't call Send at all".
    send_err = _client_error(
        lambda: invoicing.send_procurement_portal_validation(ProcurementPortalPreferenceArn=arn)
    )
    assert send_err["Code"] == "ValidationException", (
        f"expected the undeliverable test e-invoice to be rejected, got {send_err['Code']!r}"
    )
    expected_send_message = (
        f"We were unable to deliver the test e-invoice to the endpoint {_INSTANCE_ENDPOINT}/cxml/invoices. "
        "Please confirm the endpoint URL is correct and reachable, then try again."
    )
    assert send_err["Message"] == expected_send_message, (
        f"expected message {expected_send_message!r}, got {send_err['Message']!r}"
    )

    # A rejected SendProcurementPortalValidation still bumps Version (the
    # delivery attempt is recorded even though it failed) -- so the invariant this check can actually hold the target to
    # is "advances by exactly one", not "unaffected by a failed call".
    mid = invoicing.get_procurement_portal_preference(
        ProcurementPortalPreferenceArn=arn
    )["ProcurementPortalPreference"]
    assert mid["EinvoiceDeliveryPreferenceStatus"] == "PENDING_VERIFICATION", mid["EinvoiceDeliveryPreferenceStatus"]
    assert mid["PurchaseOrderRetrievalPreferenceStatus"] == "PENDING_VERIFICATION", mid["PurchaseOrderRetrievalPreferenceStatus"]
    assert mid["Version"] == before["Version"] + 1, (
        f"expected the failed send to advance Version by exactly 1 from {before['Version']!r}, got {mid['Version']!r}"
    )

    # Overly-permissive check: verifying a code is rejected when no
    # validation was ever actually issued for this preference (the send
    # above never got a code out to us), not accepted as if one were
    # pending.
    verify_err = _client_error(
        lambda: invoicing.verify_procurement_portal_validation(
            ProcurementPortalPreferenceArn=arn, Code="definitely-the-wrong-code-000000"
        )
    )
    assert verify_err["Code"] == "ValidationException", f"expected a rejection, got {verify_err['Code']!r}"
    expected_verify_message = "The code you entered is invalid. Attempt 1 of 3 failed. Please try again."
    assert verify_err["Message"] == expected_verify_message, (
        f"expected message {expected_verify_message!r}, got {verify_err['Message']!r}"
    )

    after = invoicing.get_procurement_portal_preference(
        ProcurementPortalPreferenceArn=arn
    )["ProcurementPortalPreference"]
    assert after["EinvoiceDeliveryPreferenceStatus"] == "PENDING_VERIFICATION", after["EinvoiceDeliveryPreferenceStatus"]
    assert after["PurchaseOrderRetrievalPreferenceStatus"] == "PENDING_VERIFICATION", after["PurchaseOrderRetrievalPreferenceStatus"]
    assert after["Version"] == mid["Version"] + 1, (
        f"expected the rejected verify to also advance Version by exactly 1 from {mid['Version']!r}, got {after['Version']!r}"
    )


_INSTANCE_ENDPOINT = "https://sim2real-behav.example.com/procurement-portal"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a
    target accepting input real AWS refuses must not read as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _clear_portal_preference(ctx, portal_name: str) -> None:
    """Remove any pre-existing preference for portal_name (e.g. leftover from
    a prior interrupted run), since an account may hold at most one per
    portal name and this check must not depend on ambient state."""
    invoicing = ctx.client("invoicing")
    for pref in invoicing.list_procurement_portal_preferences(MaxResults=100)["ProcurementPortalPreferences"]:
        if pref["ProcurementPortalName"] == portal_name:
            _safe_delete_preference(ctx, pref["ProcurementPortalPreferenceArn"])


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
                ProcurementPortalSharedSecret="sim2real-shared-secret-value",
                ProcurementPortalInstanceEndpoint=_INSTANCE_ENDPOINT,
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


