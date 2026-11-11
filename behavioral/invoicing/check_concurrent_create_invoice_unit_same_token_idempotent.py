"""concurrent-create-invoice-unit-same-token-idempotent."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-create-invoice-unit-same-token-idempotent"
GROUP = "concurrency"
SERVICES = ["invoicing"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent CreateInvoiceUnit calls that share the same ClientToken and
    identical parameters must all resolve to exactly one InvoiceUnitArn -
    idempotency holds under contention, not just sequentially."""
    invoicing = ctx.client("invoicing")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-iu-")
    token = ctx.unique_name("sim2real-tok-")

    kwargs = dict(
        Name=name,
        InvoiceReceiver=account_id,
        Rule={"LinkedAccounts": [account_id], "BillSourceAccounts": []},
        ClientToken=token,
        ResourceTags=[
            {"Key": "sim2real-env", "Value": "behavioral"},
            {"Key": "sim2real-owner", "Value": "invoicing-suite"},
        ],
    )

    racer_count = 6

    def _racer(_i):
        return invoicing.create_invoice_unit(**kwargs)["InvoiceUnitArn"]

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        arns = list(pool.map(_racer, range(racer_count)))

    ctx.on_cleanup(lambda: _safe_delete_invoice_unit(ctx, arns[0]))

    distinct = set(arns)
    assert len(distinct) == 1, f"expected all {racer_count} racers to converge on 1 ARN, got {distinct!r}"

    listed = invoicing.list_invoice_units(Filters={"Names": [name]}, MaxResults=10)
    assert len(listed["InvoiceUnits"]) == 1, "concurrent idempotent creates must not duplicate the invoice unit"


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
