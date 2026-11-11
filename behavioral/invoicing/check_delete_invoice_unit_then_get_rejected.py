"""delete-invoice-unit-then-get-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-invoice-unit-then-get-rejected"
GROUP = "overly-permissive"
SERVICES = ["invoicing"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteInvoiceUnit, GetInvoiceUnit and UpdateInvoiceUnit on the ARN fail
    with ResourceNotFoundException and its exact message, the unit is no longer listed,
    and a second unit is still readable."""
    invoicing = ctx.client("invoicing")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-iu-")

    arn = invoicing.create_invoice_unit(
        Name=name,
        InvoiceReceiver=account_id,
        Rule={"LinkedAccounts": [account_id], "BillSourceAccounts": []},
        ResourceTags=[
            {"Key": "sim2real-env", "Value": "behavioral"},
            {"Key": "sim2real-owner", "Value": "invoicing-suite"},
        ],
    )["InvoiceUnitArn"]

    # Baseline: it exists.
    baseline = invoicing.get_invoice_unit(InvoiceUnitArn=arn)["InvoiceUnitArn"]
    assert baseline == arn, f"expected baseline GetInvoiceUnit to echo {arn!r}, got {baseline!r}"

    invoicing.delete_invoice_unit(InvoiceUnitArn=arn)

    not_found_message = "The resource could not be found."
    get_err = _client_error(lambda: invoicing.get_invoice_unit(InvoiceUnitArn=arn))
    assert get_err["Code"] == "ResourceNotFoundException", (
        f"expected GetInvoiceUnit on a deleted ARN to raise ResourceNotFoundException, got {get_err['Code']!r}"
    )
    assert get_err["Message"] == not_found_message, (
        f"expected message {not_found_message!r}, got {get_err['Message']!r}"
    )

    # A mutation on the dead ARN must fail the same way a read does -- the
    # ARN is gone, not merely unreadable.
    update_err = _client_error(
        lambda: invoicing.update_invoice_unit(InvoiceUnitArn=arn, Description="post-delete update")
    )
    assert update_err["Code"] == "ResourceNotFoundException", (
        f"expected UpdateInvoiceUnit on a deleted ARN to raise ResourceNotFoundException, got {update_err['Code']!r}"
    )
    assert update_err["Message"] == not_found_message, (
        f"expected message {not_found_message!r}, got {update_err['Message']!r}"
    )

    listed = invoicing.list_invoice_units(Filters={"Names": [name]}, MaxResults=10)
    assert listed["InvoiceUnits"] == [], "deleted unit must not appear in the current listing"

    # Positive control: the API is still functional for a fresh resource.
    control_name = ctx.unique_name("sim2real-iu-control-")
    control_arn = invoicing.create_invoice_unit(
        Name=control_name,
        InvoiceReceiver=account_id,
        Rule={"LinkedAccounts": [account_id], "BillSourceAccounts": []},
        ResourceTags=[
            {"Key": "sim2real-env", "Value": "behavioral"},
            {"Key": "sim2real-owner", "Value": "invoicing-suite"},
        ],
    )["InvoiceUnitArn"]
    ctx.on_cleanup(lambda: _safe_delete_invoice_unit(ctx, control_arn))
    control_got_name = invoicing.get_invoice_unit(InvoiceUnitArn=control_arn)["Name"]
    assert control_got_name == control_name, (
        f"expected control unit's Name to be {control_name!r}, got {control_got_name!r}"
    )


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
