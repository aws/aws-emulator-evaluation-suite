"""list-invoice-units-filtered-by-name-contains-created."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-invoice-units-filtered-by-name-contains-created"
GROUP = "crud"
SERVICES = ["invoicing"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListInvoiceUnits with a Filters.Names selector returns exactly the
    matching invoice unit(s), with fields consistent with GetInvoiceUnit; once
    DeleteInvoiceUnit removes it, the same filter returns nothing."""
    invoicing = ctx.client("invoicing")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-iu-")

    arn = invoicing.create_invoice_unit(
        Name=name,
        InvoiceReceiver=account_id,
        Rule={"LinkedAccounts": [account_id], "BillSourceAccounts": []},
        ResourceTags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["InvoiceUnitArn"]
    ctx.on_cleanup(lambda: _safe_delete_invoice_unit(ctx, arn))

    resp = invoicing.list_invoice_units(Filters={"Names": [name]}, MaxResults=10)
    units = resp["InvoiceUnits"]
    assert len(units) == 1, f"expected exactly 1 unit named {name!r}, got {units!r}"
    listed = units[0]
    assert listed["InvoiceUnitArn"] == arn, f"expected arn {arn!r}, got {listed['InvoiceUnitArn']!r}"
    assert listed["Name"] == name, f"expected name {name!r}, got {listed['Name']!r}"
    assert listed["InvoiceReceiver"] == account_id, (
        f"expected receiver {account_id!r}, got {listed['InvoiceReceiver']!r}"
    )

    # The listing's fields must agree with an independent read of the same
    # unit through GetInvoiceUnit -- not just with what we supplied.
    got = invoicing.get_invoice_unit(InvoiceUnitArn=arn)
    for field in ("InvoiceUnitArn", "Name", "InvoiceReceiver", "Description", "TaxInheritanceDisabled", "LastModified"):
        assert listed.get(field) == got.get(field), (
            f"list/get disagree on {field}: list={listed.get(field)!r} get={got.get(field)!r}"
        )
    assert listed.get("Rule") == got.get("Rule"), f"list/get disagree on Rule: list={listed.get('Rule')!r} get={got.get('Rule')!r}"

    invoicing.delete_invoice_unit(InvoiceUnitArn=arn)
    after_delete = invoicing.list_invoice_units(Filters={"Names": [name]}, MaxResults=10)["InvoiceUnits"]
    assert after_delete == [], f"deleted unit must not appear in the filtered listing, got {after_delete!r}"


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
