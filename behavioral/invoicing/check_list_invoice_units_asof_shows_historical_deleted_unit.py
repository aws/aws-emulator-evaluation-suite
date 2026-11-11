"""list-invoice-units-asof-shows-historical-deleted-unit."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-invoice-units-asof-shows-historical-deleted-unit"
GROUP = "state"
SERVICES = ["invoicing"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListInvoiceUnits with an AsOf timestamp taken before deletion still
    surfaces a since-deleted invoice unit (point-in-time history), while a
    lookup with no AsOf (now, post-delete) omits it."""
    invoicing = ctx.client("invoicing")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-iu-")

    arn = invoicing.create_invoice_unit(
        Name=name,
        InvoiceReceiver=account_id,
        Rule={"LinkedAccounts": [account_id], "BillSourceAccounts": []},
        ResourceTags=[{"Key": "sim2real-env", "Value": "behavioral"}],
    )["InvoiceUnitArn"]
    ctx.on_cleanup(lambda: _safe_delete_invoice_unit(ctx, arn))

    # Use the server's own recorded LastModified (its creation time) as the
    # pre-delete snapshot instant. That is authoritative ground truth -- the
    # unit provably existed at that exact instant -- and needs no wall-clock
    # wait to establish, since the delete call below necessarily happens
    # later in real time than this already-completed create/get round trip.
    created = invoicing.get_invoice_unit(InvoiceUnitArn=arn)
    assert created["InvoiceUnitArn"] == arn, f"expected {arn}, got {created.get('InvoiceUnitArn')}"
    as_of_before_delete = created["LastModified"]

    invoicing.delete_invoice_unit(InvoiceUnitArn=arn)

    historical = invoicing.list_invoice_units(
        Filters={"Names": [name]}, AsOf=as_of_before_delete
    )
    historical_arns = {u["InvoiceUnitArn"] for u in historical["InvoiceUnits"]}
    assert arn in historical_arns, "deleted unit should still appear in a pre-delete AsOf snapshot"

    current = invoicing.list_invoice_units(Filters={"Names": [name]})
    current_arns = {u["InvoiceUnitArn"] for u in current["InvoiceUnits"]}
    assert arn not in current_arns, "deleted unit should be absent from the current listing"


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
