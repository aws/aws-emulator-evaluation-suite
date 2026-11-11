"""concurrent-create-budget-same-name-single-winner."""
from __future__ import annotations

import concurrent.futures as cf

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-budget-same-name-single-winner"
GROUP = "concurrency"
SERVICES = ["budgets"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Racing CreateBudget calls for the same BudgetName: exactly one wins, the rest get DuplicateRecordException."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    name = ctx.unique_name("sim2real-budget-race-")
    body = {
        "BudgetName": name,
        "BudgetLimit": {"Amount": "50.0", "Unit": "USD"},
        "TimeUnit": "MONTHLY",
        "BudgetType": "COST",
    }
    ctx.on_cleanup(lambda: _safe_delete(budgets, account_id, name))

    def attempt(_):
        try:
            budgets.create_budget(AccountId=account_id, Budget=body)
            return "success"
        except ClientError as err:
            return err.response["Error"]["Code"]

    with cf.ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(attempt, range(5)))

    successes = [r for r in results if r == "success"]
    duplicates = [r for r in results if r == "DuplicateRecordException"]
    assert len(successes) == 1, f"expected exactly one winner, got {results}"
    assert len(duplicates) == 4, f"expected 4 DuplicateRecordException losers, got {results}"

    described = budgets.describe_budget(AccountId=account_id, BudgetName=name)["Budget"]
    assert described["BudgetName"] == name, f"expected {name!r}, got {described.get('BudgetName')!r}"

    matching = [b for b in _list_all_budgets(budgets, account_id) if b["BudgetName"] == name]
    assert len(matching) == 1, f"expected exactly one budget named {name!r}, found {len(matching)}"


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _list_all_budgets(budgets, account_id):
    out = []
    token = None
    while True:
        kwargs = {"AccountId": account_id}
        if token:
            kwargs["NextToken"] = token
        page = budgets.describe_budgets(**kwargs)
        out.extend(page["Budgets"])
        token = page.get("NextToken")
        if not token:
            return out


def _safe_delete(budgets, account_id, name):
    try:
        budgets.delete_budget(AccountId=account_id, BudgetName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
