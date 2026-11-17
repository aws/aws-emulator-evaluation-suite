"""disassociate-budget-never-associated-with-portfolio-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-budget-never-associated-with-portfolio-rejected"
GROUP = "budgets"
SERVICES = ["budgets", "servicecatalog"]


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
    """DisassociateBudgetFromResource is refused with ResourceNotFoundException and its exact
    message when the named budget was never associated with the portfolio, leaving the
    portfolio's associated-budget list unaffected; the identical call succeeds once associated.
    """
    budgets = ctx.client("budgets")
    sc = ctx.client("servicecatalog")

    held_budget = ctx.unique_name("sim2real-sc-budget-")
    budgets.create_budget(
        AccountId=ctx.account,
        Budget={
            "BudgetName": held_budget,
            "BudgetLimit": {"Amount": "100", "Unit": "USD"},
            "TimeUnit": "MONTHLY",
            "BudgetType": "COST",
        },
    )
    ctx.on_cleanup(_teardown(
        lambda: budgets.delete_budget(AccountId=ctx.account, BudgetName=held_budget),
        "NotFoundException",
    ))

    other_budget = ctx.unique_name("sim2real-sc-budget-")
    budgets.create_budget(
        AccountId=ctx.account,
        Budget={
            "BudgetName": other_budget,
            "BudgetLimit": {"Amount": "50", "Unit": "USD"},
            "TimeUnit": "MONTHLY",
            "BudgetType": "COST",
        },
    )
    ctx.on_cleanup(_teardown(
        lambda: budgets.delete_budget(AccountId=ctx.account, BudgetName=other_budget),
        "NotFoundException",
    ))

    portfolio_id = sc.create_portfolio(
        DisplayName=ctx.unique_name("sim2real-sc-pf-"), ProviderName="sim2real",
        Description="sim2real service-catalog behavioral check",
    )["PortfolioDetail"]["Id"]
    ctx.on_cleanup(_teardown(lambda: sc.delete_portfolio(Id=portfolio_id), "ResourceNotFoundException"))

    # ---- positive control: a real association is visible ----
    sc.associate_budget_with_resource(BudgetName=held_budget, ResourceId=portfolio_id)
    ctx.on_cleanup(_teardown(
        lambda: sc.disassociate_budget_from_resource(BudgetName=held_budget, ResourceId=portfolio_id),
        "ResourceNotFoundException",
    ))
    control = sc.describe_portfolio(Id=portfolio_id)["Budgets"]
    assert control == [{"BudgetName": held_budget}], (
        f"the control association did not register: DescribePortfolio returned {control!r}"
    )

    # ---- break exactly one thing: disassociate a budget that was never associated ----
    code, message = _error(lambda: sc.disassociate_budget_from_resource(
        BudgetName=other_budget, ResourceId=portfolio_id))
    assert code == "ResourceNotFoundException", (
        f"disassociating a never-associated budget answered {code!r}, "
        f"expected 'ResourceNotFoundException'"
    )
    expected_message = (
        f"Budget with name {other_budget} is not associated with resource {portfolio_id}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # ---- the effect is absent: the real association is untouched ----
    after_refusal = sc.describe_portfolio(Id=portfolio_id)["Budgets"]
    assert after_refusal == [{"BudgetName": held_budget}], (
        f"the refused disassociation of {other_budget!r} changed the portfolio's list to "
        f"{after_refusal!r}, expected it to stay [{{'BudgetName': {held_budget!r}}}]"
    )

    # ---- restore: a portfolio holds one budget at a time, so free the slot, then the identical
    # disassociate call succeeds once that budget really is associated ----
    sc.disassociate_budget_from_resource(BudgetName=held_budget, ResourceId=portfolio_id)
    freed = sc.describe_portfolio(Id=portfolio_id)["Budgets"]
    assert freed == [], f"freeing the slot left DescribePortfolio returning {freed!r}, expected []"

    sc.associate_budget_with_resource(BudgetName=other_budget, ResourceId=portfolio_id)
    ctx.on_cleanup(_teardown(
        lambda: sc.disassociate_budget_from_resource(BudgetName=other_budget, ResourceId=portfolio_id),
        "ResourceNotFoundException",
    ))
    now_associated = sc.describe_portfolio(Id=portfolio_id)["Budgets"]
    assert now_associated == [{"BudgetName": other_budget}], (
        f"associating {other_budget!r} did not register: DescribePortfolio returned {now_associated!r}"
    )

    sc.disassociate_budget_from_resource(BudgetName=other_budget, ResourceId=portfolio_id)
    after_restore = sc.describe_portfolio(Id=portfolio_id)["Budgets"]
    assert after_restore == [], (
        f"the identical disassociate call, now that {other_budget!r} was really associated, "
        f"left DescribePortfolio returning {after_restore!r}, expected []"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
