"""portfolio-budget-association-reflects-in-list."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "portfolio-budget-association-reflects-in-list"
GROUP = "budgets"
SERVICES = ["budgets", "servicecatalog"]


def _ignore_not_found(fn, *not_found: str) -> None:
    """Teardown where only the resource's own not-found codes mean it is already gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in not_found:
            raise


@tags("axis:happy-path", "concern:representation", "plane:control", "cap:c1")
def run(ctx) -> None:
    """ListBudgetsForResource on a portfolio tracks exactly the budgets currently
    associated with it: empty before association, the one budget after, empty again
    after disassociation."""
    budgets = ctx.client("budgets")
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
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: budgets.delete_budget(AccountId=ctx.account, BudgetName=budget_name),
        "NotFoundException",
    ))

    portfolio_id = sc.create_portfolio(
        DisplayName=ctx.unique_name("sim2real-sc-pf-"), ProviderName="sim2real",
        Description="sim2real service-catalog behavioral check",
    )["PortfolioDetail"]["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: sc.delete_portfolio(Id=portfolio_id), "ResourceNotFoundException",
    ))

    before = sc.list_budgets_for_resource(ResourceId=portfolio_id)["Budgets"]
    assert before == [], f"a fresh portfolio already lists budgets: {before!r}, expected []"

    sc.associate_budget_with_resource(BudgetName=budget_name, ResourceId=portfolio_id)
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: sc.disassociate_budget_from_resource(
            BudgetName=budget_name, ResourceId=portfolio_id),
        "ResourceNotFoundException",
    ))

    after_associate = sc.list_budgets_for_resource(ResourceId=portfolio_id)["Budgets"]
    assert after_associate == [{"BudgetName": budget_name}], (
        f"after associating {budget_name!r}, ListBudgetsForResource returned "
        f"{after_associate!r}, expected exactly [{{'BudgetName': {budget_name!r}}}]"
    )

    sc.disassociate_budget_from_resource(BudgetName=budget_name, ResourceId=portfolio_id)

    after_disassociate = sc.list_budgets_for_resource(ResourceId=portfolio_id)["Budgets"]
    assert after_disassociate == [], (
        f"after disassociating the only budget, ListBudgetsForResource returned "
        f"{after_disassociate!r}, expected []"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
