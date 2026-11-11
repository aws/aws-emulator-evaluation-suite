"""tag-untag-resource-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-untag-resource-round-trip"
GROUP = "tagging"
SERVICES = ["invoicing"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches a tag visible via ListTagsForResource; UntagResource
    removes it and the removal is reflected on the next list call."""
    invoicing = ctx.client("invoicing")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-iu-")

    arn = invoicing.create_invoice_unit(
        Name=name,
        InvoiceReceiver=account_id,
        Rule={"LinkedAccounts": [account_id], "BillSourceAccounts": []},
    )["InvoiceUnitArn"]
    ctx.on_cleanup(lambda: _safe_delete_invoice_unit(ctx, arn))

    initial = invoicing.list_tags_for_resource(ResourceArn=arn)["ResourceTags"]
    assert initial == [], f"expected a freshly created invoice unit to have no tags, got {initial!r}"

    invoicing.tag_resource(
        ResourceArn=arn, ResourceTags=[{"Key": "sim2real-stage", "Value": "beta"}]
    )
    tags = {t["Key"]: t["Value"] for t in invoicing.list_tags_for_resource(ResourceArn=arn)["ResourceTags"]}
    assert tags == {"sim2real-stage": "beta"}, f"expected only the newly attached tag, got {tags!r}"

    invoicing.untag_resource(ResourceArn=arn, ResourceTagKeys=["sim2real-stage"])
    remaining = invoicing.list_tags_for_resource(ResourceArn=arn)["ResourceTags"]
    assert remaining == [], f"expected tag removed, still present: {remaining!r}"


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
