"""tag-resource-exceeds-quota-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-exceeds-quota-rejected"
GROUP = "overly-permissive"
SERVICES = ["invoicing"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource succeeds up to an invoice unit's tag quota, the batch that would
    exceed it fails with ServiceQuotaExceededException and its exact message and adds no
    tags, and after untagging the same batch succeeds."""
    from botocore.exceptions import ClientError

    invoicing = ctx.client("invoicing")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-iu-")

    arn = invoicing.create_invoice_unit(
        Name=name,
        InvoiceReceiver=account_id,
        Rule={"LinkedAccounts": [account_id], "BillSourceAccounts": []},
    )["InvoiceUnitArn"]
    ctx.on_cleanup(lambda: _safe_delete_invoice_unit(ctx, arn))

    # Discover the account's per-resource tag quota by adding tags
    # in small batches until a ServiceQuotaExceededException is hit, rather
    # than assuming a specific limit (the API's per-call array max of 200 is
    # not necessarily the per-resource quota).
    batch_size = 10
    quota_error_code = None
    quota_error_message = None
    count_before_final_batch = 0
    failing_batch = None
    prior_batch_keys = None
    for batch_start in range(0, 200, batch_size):
        count_before_final_batch = len(
            invoicing.list_tags_for_resource(ResourceArn=arn)["ResourceTags"]
        )
        batch = [
            {"Key": f"sim2real-quota-{i}", "Value": str(i)}
            for i in range(batch_start, batch_start + batch_size)
        ]
        try:
            invoicing.tag_resource(ResourceArn=arn, ResourceTags=batch)
        except ClientError as err:
            quota_error_code = err.response["Error"].get("Code")
            quota_error_message = err.response["Error"].get("Message")
            failing_batch = batch
            prior_batch_keys = [
                f"sim2real-quota-{i}" for i in range(batch_start - batch_size, batch_start)
            ]
            break
    else:
        raise AssertionError("expected to hit a tag quota within 200 tags, but never did")

    assert quota_error_code == "ServiceQuotaExceededException", (
        f"expected ServiceQuotaExceededException once the tag quota is exceeded, got {quota_error_code!r}"
    )
    expected_message = "The request exceeds the maximum number of tags allowed per resource."
    assert quota_error_message == expected_message, (
        f"expected message {expected_message!r}, got {quota_error_message!r}"
    )
    assert count_before_final_batch > 0, "expected at least one prior batch to succeed (positive control)"

    after = invoicing.list_tags_for_resource(ResourceArn=arn)["ResourceTags"]
    assert len(after) == count_before_final_batch, (
        "tag count must not change after a rejected over-quota TagResource call"
    )

    # Restore leg: the quota is a state boundary, not a fixed-invalid input.
    # Free exactly the headroom the failing batch needed (by removing the
    # immediately-prior successful batch) and demand the identical call now
    # succeeds and its tags are visible via an independent read.
    invoicing.untag_resource(ResourceArn=arn, ResourceTagKeys=prior_batch_keys)
    invoicing.tag_resource(ResourceArn=arn, ResourceTags=failing_batch)
    restored = {
        t["Key"]: t["Value"]
        for t in invoicing.list_tags_for_resource(ResourceArn=arn)["ResourceTags"]
    }
    for tag in failing_batch:
        assert restored.get(tag["Key"]) == tag["Value"], (
            f"expected {tag['Key']!r} to persist after quota headroom was restored, got {restored.get(tag['Key'])!r}"
        )
    for key in prior_batch_keys:
        assert key not in restored, f"expected untagged key {key!r} to stay removed, still present"


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
