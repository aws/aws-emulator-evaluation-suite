"""create-invoice-unit-with-resource-tags-at-creation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-invoice-unit-with-resource-tags-at-creation"
GROUP = "tagging"
SERVICES = ["invoicing"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags supplied via CreateInvoiceUnit's ResourceTags are attached at
    creation time and are visible via ListTagsForResource without any
    separate TagResource call."""
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
    ctx.on_cleanup(lambda: _safe_delete_invoice_unit(ctx, arn))

    tags = {t["Key"]: t["Value"] for t in invoicing.list_tags_for_resource(ResourceArn=arn)["ResourceTags"]}
    assert tags.get("sim2real-env") == "behavioral", f"expected sim2real-env=behavioral, got {tags!r}"
    assert tags.get("sim2real-owner") == "invoicing-suite", f"expected sim2real-owner=invoicing-suite, got {tags!r}"
    assert tags == {
        "sim2real-env": "behavioral",
        "sim2real-owner": "invoicing-suite",
    }, f"expected exactly the two ResourceTags supplied at creation, no more, got {tags!r}"


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
