"""duplicate-budget-association-and-unknown-portfolio-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-budget-association-and-unknown-portfolio-rejected"
GROUP = "budgets"
SERVICES = ["budgets", "servicecatalog"]


def _error(fn) -> tuple:
    """The (Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success
    fails."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to be refused but succeeded")


def _ignore_not_found(fn, *not_found: str) -> None:
    """Teardown where only the resource's own not-found codes mean it is already gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in not_found:
            raise


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """AssociateBudgetWithResource is refused with DuplicateResourceException when the budget is
    already associated with the resource, and with ResourceNotFoundException when the resource id
    names no portfolio; neither refusal changes the portfolio's associated-budget list."""
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

    # ---- positive control: the first association succeeds and is visible ----
    sc.associate_budget_with_resource(BudgetName=budget_name, ResourceId=portfolio_id)
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: sc.disassociate_budget_from_resource(
            BudgetName=budget_name, ResourceId=portfolio_id),
        "ResourceNotFoundException",
    ))
    listed = sc.list_budgets_for_resource(ResourceId=portfolio_id)["Budgets"]
    assert listed == [{"BudgetName": budget_name}], (
        f"the first association did not register: ListBudgetsForResource returned {listed!r}"
    )

    # ---- negative 1: associating the same budget with the same portfolio again ----
    dup_code, dup_message = _error(lambda: sc.associate_budget_with_resource(
        BudgetName=budget_name, ResourceId=portfolio_id))
    assert dup_code == "DuplicateResourceException", (
        f"re-associating an already-associated budget answered {dup_code!r}, "
        f"expected 'DuplicateResourceException'"
    )
    expected_dup_message = f"BudgetAssociation already exists on resource {portfolio_id}"
    assert dup_message == expected_dup_message, (
        f"expected message {expected_dup_message!r}, got {dup_message!r}"
    )
    after_dup = sc.list_budgets_for_resource(ResourceId=portfolio_id)["Budgets"]
    assert after_dup == [{"BudgetName": budget_name}], (
        f"a refused duplicate association changed the list to {after_dup!r}, "
        f"expected it to stay [{{'BudgetName': {budget_name!r}}}]"
    )

    # ---- negative 2: associating with a resource id that names no portfolio ----
    unknown_id = ctx.unique_name("port-sim2real-missing-")
    unk_code, unk_message = _error(lambda: sc.associate_budget_with_resource(
        BudgetName=budget_name, ResourceId=unknown_id))
    assert unk_code == "ResourceNotFoundException", (
        f"associating with an unknown portfolio id answered {unk_code!r}, "
        f"expected 'ResourceNotFoundException'"
    )
    expected_unk_message = f"Portfolio {unknown_id} not found."
    assert unk_message == expected_unk_message, (
        f"expected message {expected_unk_message!r}, got {unk_message!r}"
    )

    # ...and the real portfolio's association is unaffected by the unknown-resource attempt.
    final = sc.list_budgets_for_resource(ResourceId=portfolio_id)["Budgets"]
    assert final == [{"BudgetName": budget_name}], (
        f"the unknown-portfolio attempt left the real portfolio's list as {final!r}, "
        f"expected it to stay [{{'BudgetName': {budget_name!r}}}]"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
