"""budget-association-visible-in-product-and-portfolio-describes."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "budget-association-visible-in-product-and-portfolio-describes"
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


@tags("axis:happy-path", "concern:representation", "plane:control", "cap:c1")
def run(ctx) -> None:
    """A budget associated with a product id is listed by ListBudgetsForResource and by
    DescribeProductAsAdmin; associated with a portfolio id, it is listed by DescribePortfolio.
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

    portfolio_id = sc.create_portfolio(
        DisplayName=ctx.unique_name("sim2real-sc-pf-"), ProviderName="sim2real",
        Description="sim2real service-catalog behavioral check",
    )["PortfolioDetail"]["Id"]
    ctx.on_cleanup(_teardown(lambda: sc.delete_portfolio(Id=portfolio_id), "ResourceNotFoundException"))

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

    # ---- product association: visible via ListBudgetsForResource and DescribeProductAsAdmin ----
    before_product = sc.list_budgets_for_resource(ResourceId=product_id)["Budgets"]
    assert before_product == [], (
        f"a fresh product already lists budgets: {before_product!r}, expected []"
    )

    sc.associate_budget_with_resource(BudgetName=budget_name, ResourceId=product_id)
    ctx.on_cleanup(_teardown(
        lambda: sc.disassociate_budget_from_resource(BudgetName=budget_name, ResourceId=product_id),
        "ResourceNotFoundException",
    ))

    listed_product = sc.list_budgets_for_resource(ResourceId=product_id)["Budgets"]
    assert listed_product == [{"BudgetName": budget_name}], (
        f"ListBudgetsForResource on the product returned {listed_product!r}, "
        f"expected exactly [{{'BudgetName': {budget_name!r}}}]"
    )

    admin_view = sc.describe_product_as_admin(Id=product_id)["Budgets"]
    assert admin_view == [{"BudgetName": budget_name}], (
        f"DescribeProductAsAdmin returned Budgets={admin_view!r}, "
        f"expected exactly [{{'BudgetName': {budget_name!r}}}]"
    )

    # ---- portfolio association: visible via DescribePortfolio ----
    before_portfolio = sc.describe_portfolio(Id=portfolio_id)["Budgets"]
    assert before_portfolio == [], (
        f"a fresh portfolio already lists budgets: {before_portfolio!r}, expected []"
    )

    sc.associate_budget_with_resource(BudgetName=budget_name, ResourceId=portfolio_id)
    ctx.on_cleanup(_teardown(
        lambda: sc.disassociate_budget_from_resource(BudgetName=budget_name, ResourceId=portfolio_id),
        "ResourceNotFoundException",
    ))

    after_portfolio_associate = sc.describe_portfolio(Id=portfolio_id)["Budgets"]
    assert after_portfolio_associate == [{"BudgetName": budget_name}], (
        f"DescribePortfolio returned Budgets={after_portfolio_associate!r}, "
        f"expected exactly [{{'BudgetName': {budget_name!r}}}]"
    )

    sc.disassociate_budget_from_resource(BudgetName=budget_name, ResourceId=portfolio_id)
    final_portfolio = sc.describe_portfolio(Id=portfolio_id)["Budgets"]
    assert final_portfolio == [], (
        f"after disassociating the only budget, DescribePortfolio returned {final_portfolio!r}, "
        f"expected []"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
