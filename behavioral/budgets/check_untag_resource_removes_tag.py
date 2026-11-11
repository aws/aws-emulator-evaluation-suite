"""untag-resource-removes-tag."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag"
GROUP = "tagging"
SERVICES = ["budgets"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the specified tag key, leaving the other tags intact."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    name = ctx.unique_name("sim2real-budget-untag-")
    budgets.create_budget(
        AccountId=account_id,
        Budget={
            "BudgetName": name,
            "BudgetLimit": {"Amount": "50.0", "Unit": "USD"},
            "TimeUnit": "MONTHLY",
            "BudgetType": "COST",
        },
    )
    ctx.on_cleanup(lambda: budgets.delete_budget(AccountId=account_id, BudgetName=name))

    arn = f"arn:aws:budgets::{account_id}:budget/{name}"
    budgets.tag_resource(
        ResourceARN=arn,
        ResourceTags=[
            {"Key": "sim2real-keep", "Value": "yes"},
            {"Key": "sim2real-drop", "Value": "yes"},
        ],
    )

    budgets.untag_resource(ResourceARN=arn, ResourceTagKeys=["sim2real-drop"])

    tags = budgets.list_tags_for_resource(ResourceARN=arn)["ResourceTags"]
    tag_map = {t["Key"]: t["Value"] for t in tags}
    assert "sim2real-keep" in tag_map, f"expected sim2real-keep to survive untag, tags now {tag_map}"
    assert "sim2real-drop" not in tag_map, f"expected sim2real-drop removed by untag, tags now {tag_map}"


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
