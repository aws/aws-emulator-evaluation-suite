"""associate-budget-with-unknown-product-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-budget-with-unknown-product-rejected"
GROUP = "budgets"
SERVICES = ["budgets", "s3", "servicecatalog"]

_TEMPLATE = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
})


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where only the resource's own not-found codes mean it is
    already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn) -> tuple:
    """The (Error.Code, Error.Message) ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """AssociateBudgetWithResource is refused with ResourceNotFoundException and its exact
    message when the resource id names no product, leaving a real product's list unaffected.
    """
    budgets = ctx.client("budgets")
    s3 = ctx.client("s3")
    sc = ctx.client("servicecatalog")

    budget_name = ctx.unique_name("sim2real-sc-budget-")
    budgets.create_budget(
        AccountId=ctx.account,
        Budget={
            "BudgetName": budget_name,
            "BudgetLimit": {"Amount": "100", "Unit": "USD"},
            "TimeUnit": "MONTHLY",
            "BudgetType": "COST",
        },
    )
    ctx.on_cleanup(_teardown(
        lambda: budgets.delete_budget(AccountId=ctx.account, BudgetName=budget_name),
        "NotFoundException",
    ))

    # ---- a product needs a provisioning artifact; store its minimal template in our own bucket ----
    bucket = ctx.unique_name("sim2real-sc-tmpl-")
    bucket_kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        bucket_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**bucket_kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    template_key = "template.json"
    s3.put_object(Bucket=bucket, Key=template_key, Body=_TEMPLATE.encode("utf-8"))
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=template_key))

    template_url = ctx.s3_object_url(
        f"https://s3.{ctx.region}.amazonaws.com/{bucket}/{template_key}", bucket, template_key,
    )

    product_id = sc.create_product(
        Name=ctx.unique_name("sim2real-sc-prod-"), Owner="sim2real",
        Description="sim2real service-catalog behavioral check", ProductType="CLOUD_FORMATION_TEMPLATE",
        ProvisioningArtifactParameters={
            "Name": "v1", "Info": {"LoadTemplateFromURL": template_url},
            "Type": "CLOUD_FORMATION_TEMPLATE",
        },
    )["ProductViewDetail"]["ProductViewSummary"]["ProductId"]
    ctx.on_cleanup(_teardown(lambda: sc.delete_product(Id=product_id), "ResourceNotFoundException"))

    # ---- positive control: the real product takes the association ----
    sc.associate_budget_with_resource(BudgetName=budget_name, ResourceId=product_id)
    ctx.on_cleanup(_teardown(
        lambda: sc.disassociate_budget_from_resource(BudgetName=budget_name, ResourceId=product_id),
        "ResourceNotFoundException",
    ))
    control = sc.list_budgets_for_resource(ResourceId=product_id)["Budgets"]
    assert control == [{"BudgetName": budget_name}], (
        f"the control association did not register: ListBudgetsForResource returned {control!r}"
    )

    # ---- break exactly one thing: the resource id names no product ----
    unknown_id = ctx.unique_name("prod-sim2real-missing-")
    code, message = _error(lambda: sc.associate_budget_with_resource(
        BudgetName=budget_name, ResourceId=unknown_id))
    assert code == "ResourceNotFoundException", (
        f"associating with an unknown product id answered {code!r}, "
        f"expected 'ResourceNotFoundException'"
    )
    expected_message = f"Product {unknown_id} not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # ---- the real product's association is unaffected by the unknown-product attempt ----
    after_refusal = sc.list_budgets_for_resource(ResourceId=product_id)["Budgets"]
    assert after_refusal == [{"BudgetName": budget_name}], (
        f"the unknown-product attempt left the real product's list as {after_refusal!r}, "
        f"expected it to stay [{{'BudgetName': {budget_name!r}}}]"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
