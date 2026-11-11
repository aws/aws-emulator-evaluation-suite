"""create-invoice-unit-client-token-idempotent."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-invoice-unit-client-token-idempotent"
GROUP = "idempotency"
SERVICES = ["invoicing"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateInvoiceUnit enforces name uniqueness: a second unit with the same Name
    fails with ValidationException and its exact message while the first exists, and
    after the delete the Name creates a new unit."""
    invoicing = ctx.client("invoicing")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-iu-")

    kwargs = dict(
        Name=name,
        InvoiceReceiver=account_id,
        Rule={"LinkedAccounts": [account_id], "BillSourceAccounts": []},
    )

    live_arns = []
    ctx.on_cleanup(lambda: _safe_delete_all(ctx, live_arns))

    arn1 = invoicing.create_invoice_unit(**kwargs)["InvoiceUnitArn"]
    live_arns.append(arn1)

    from botocore.exceptions import ClientError

    try:
        invoicing.create_invoice_unit(**kwargs)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"]["Message"]
        assert code == "ValidationException", (
            f"expected ValidationException for a duplicate Name, got {code}: {message}"
        )
        expected_message = f"Invoice Unit already exists with name: <{name}>"
        assert message == expected_message, (
            f"expected duplicate-name message {expected_message!r}, got {message!r}"
        )
    else:
        raise AssertionError("CreateInvoiceUnit accepted a duplicate Name instead of rejecting it")

    listed = invoicing.list_invoice_units(Filters={"Names": [name]}, MaxResults=10)
    assert len(listed["InvoiceUnits"]) == 1, "the rejected duplicate must not appear alongside the original"

    invoicing.delete_invoice_unit(InvoiceUnitArn=arn1)
    live_arns.remove(arn1)

    deadline = time.monotonic() + 30
    arn2 = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            arn2 = invoicing.create_invoice_unit(**kwargs)["InvoiceUnitArn"]
            break
        except ClientError as err:
            last_err = err
            time.sleep(3)
    if arn2 is None:
        raise AssertionError(f"Name {name!r} never became available after deleting the original: {last_err}")
    live_arns.append(arn2)

    assert arn2 != arn1, "recreation after delete must mint a new ARN, not resurrect the deleted one"

    listed_again = invoicing.list_invoice_units(Filters={"Names": [name]}, MaxResults=10)
    assert len(listed_again["InvoiceUnits"]) == 1, "the Name is usable again after the original was deleted"


def _safe_delete_all(ctx, arns: list) -> None:
    from botocore.exceptions import ClientError

    for arn in list(arns):
        try:
            ctx.client("invoicing").delete_invoice_unit(InvoiceUnitArn=arn)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
