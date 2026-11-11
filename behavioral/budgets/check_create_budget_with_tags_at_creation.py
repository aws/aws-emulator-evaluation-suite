"""create-budget-with-tags-at-creation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-budget-with-tags-at-creation"
GROUP = "tagging"
SERVICES = ["budgets"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ResourceTags passed to CreateBudget are attached to the budget's ARN and visible via ListTagsForResource."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    name = ctx.unique_name("sim2real-budget-createtags-")
    budgets.create_budget(
        AccountId=account_id,
        Budget={
            "BudgetName": name,
            "BudgetLimit": {"Amount": "50.0", "Unit": "USD"},
            "TimeUnit": "MONTHLY",
            "BudgetType": "COST",
        },
        ResourceTags=[{"Key": "sim2real-env", "Value": "behavioral-test"}],
    )
    ctx.on_cleanup(lambda: budgets.delete_budget(AccountId=account_id, BudgetName=name))

    arn = f"arn:aws:budgets::{account_id}:budget/{name}"
    tags = budgets.list_tags_for_resource(ResourceARN=arn)["ResourceTags"]
    tag_map = {t["Key"]: t["Value"] for t in tags}
    assert tag_map.get("sim2real-env") == "behavioral-test", (
        f"expected sim2real-env=behavioral-test on {arn}, got tags {tag_map!r}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
