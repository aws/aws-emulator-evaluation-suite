"""create-invoice-unit-invalid-receiver-format-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-invoice-unit-invalid-receiver-format-rejected"
GROUP = "overly-permissive"
SERVICES = ["invoicing"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateInvoiceUnit rejects an InvoiceReceiver that isn't a 12-digit
    account id with ValidationException, no unit is created, and the API
    still accepts a well-formed request (positive control)."""
    invoicing = ctx.client("invoicing")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bad_name = ctx.unique_name("sim2real-iu-bad-")

    error = _client_error(
        lambda: invoicing.create_invoice_unit(
            Name=bad_name,
            InvoiceReceiver="NOT-AN-ACCOUNT",  # not a 12-digit account id
            Rule={"LinkedAccounts": [account_id], "BillSourceAccounts": []},
        )
    )
    assert error["Code"] == "ValidationException", (
        f"expected ValidationException for a malformed InvoiceReceiver, got {error['Code']!r}"
    )
    expected_message = (
        "1 validation error detected: Value at 'invoiceReceiver' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: \\d{12}"
    )
    assert error["Message"] == expected_message, (
        f"expected message {expected_message!r}, got {error['Message']!r}"
    )

    listed = invoicing.list_invoice_units(Filters={"Names": [bad_name]}, MaxResults=10)
    assert listed["InvoiceUnits"] == [], "rejected create must not have created an invoice unit"

    # Positive control: a well-formed request against the same account succeeds.
    good_name = ctx.unique_name("sim2real-iu-good-")
    good_arn = invoicing.create_invoice_unit(
        Name=good_name,
        InvoiceReceiver=account_id,
        Rule={"LinkedAccounts": [account_id], "BillSourceAccounts": []},
        ResourceTags=[{"Key": "sim2real-owner", "Value": "invoicing-suite"}],
    )["InvoiceUnitArn"]
    ctx.on_cleanup(lambda: _safe_delete_invoice_unit(ctx, good_arn))
    good_receiver = invoicing.get_invoice_unit(InvoiceUnitArn=good_arn)["InvoiceReceiver"]
    assert good_receiver == account_id, f"expected the well-formed positive control to persist InvoiceReceiver={account_id}, got {good_receiver!r}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a
    target accepting input real AWS refuses must not read as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete_invoice_unit(ctx, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ctx.client("invoicing").delete_invoice_unit(InvoiceUnitArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
