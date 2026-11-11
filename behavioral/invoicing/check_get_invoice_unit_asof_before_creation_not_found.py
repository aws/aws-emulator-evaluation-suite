"""get-invoice-unit-asof-before-creation-not-found."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "get-invoice-unit-asof-before-creation-not-found"
GROUP = "state"
SERVICES = ["invoicing"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetInvoiceUnit with an AsOf timestamp that predates the unit's creation
    reports ResourceNotFoundException, while a lookup with no AsOf (now)
    succeeds for the very same ARN."""
    invoicing = ctx.client("invoicing")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-iu-")

    arn = invoicing.create_invoice_unit(
        Name=name,
        InvoiceReceiver=account_id,
        Rule={"LinkedAccounts": [account_id], "BillSourceAccounts": []},
        ResourceTags=[{"Key": "sim2real-owner", "Value": "invoicing-suite"}],
    )["InvoiceUnitArn"]
    ctx.on_cleanup(lambda: _safe_delete_invoice_unit(ctx, arn))

    # Positive control: the same ARN resolves fine as of now, and its own
    # server-recorded LastModified is authoritative ground truth for "when it
    # started existing" -- no wall-clock wait is needed to establish that.
    now = invoicing.get_invoice_unit(InvoiceUnitArn=arn)
    assert now["InvoiceUnitArn"] == arn, f"expected {arn!r}, got {now['InvoiceUnitArn']!r}"
    assert now["Name"] == name, f"expected name {name!r}, got {now['Name']!r}"
    creation_time = now["LastModified"]

    before_creation = creation_time - datetime.timedelta(minutes=5)
    error = _client_error(
        lambda: invoicing.get_invoice_unit(InvoiceUnitArn=arn, AsOf=before_creation)
    )
    assert error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a pre-creation AsOf, got {error['Code']!r}"
    )
    expected_message = "The resource could not be found."
    assert error["Message"] == expected_message, (
        f"expected message {expected_message!r}, got {error['Message']!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(
        f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


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
