"""create-get-invoice-unit-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-get-invoice-unit-round-trip"
GROUP = "crud"
SERVICES = ["invoicing"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateInvoiceUnit persists Name/InvoiceReceiver/Description/Rule/default
    TaxInheritanceDisabled exactly as supplied, visible via GetInvoiceUnit."""
    invoicing = ctx.client("invoicing")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-iu-")

    created = invoicing.create_invoice_unit(
        Name=name,
        InvoiceReceiver=account_id,
        Description="behavioral fidelity check unit",
        Rule={"LinkedAccounts": [account_id], "BillSourceAccounts": []},
    )
    arn = created["InvoiceUnitArn"]
    ctx.on_cleanup(lambda: _safe_delete_invoice_unit(ctx, arn))

    got = invoicing.get_invoice_unit(InvoiceUnitArn=arn)
    assert got["InvoiceUnitArn"] == arn, f"expected arn {arn!r}, got {got['InvoiceUnitArn']!r}"
    assert got["Name"] == name, f"expected name {name!r}, got {got['Name']!r}"
    assert got["InvoiceReceiver"] == account_id, (
        f"expected InvoiceReceiver {account_id!r}, got {got['InvoiceReceiver']!r}"
    )
    assert got["Description"] == "behavioral fidelity check unit", (
        f"expected Description 'behavioral fidelity check unit', got {got['Description']!r}"
    )
    assert got["TaxInheritanceDisabled"] is False, (
        f"expected default TaxInheritanceDisabled False, got {got['TaxInheritanceDisabled']!r}"
    )
    assert got["Rule"]["LinkedAccounts"] == [account_id], (
        f"expected Rule.LinkedAccounts {[account_id]!r}, got {got['Rule']['LinkedAccounts']!r}"
    )
    assert got["Rule"].get("BillSourceAccounts", []) == [], (
        f"expected Rule.BillSourceAccounts absent-or-empty, got {got['Rule'].get('BillSourceAccounts')!r}"
    )
    assert "LastModified" in got, f"expected LastModified in response, got keys {sorted(got)!r}"


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
