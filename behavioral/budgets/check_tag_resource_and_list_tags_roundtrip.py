"""tag-resource-and-list-tags-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-and-list-tags-roundtrip"
GROUP = "tagging"
SERVICES = ["budgets"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags to an existing budget's ARN, visible via ListTagsForResource."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    name = ctx.unique_name("sim2real-budget-tagrt-")
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
            {"Key": "sim2real-owner", "Value": "behavioral-suite"},
            {"Key": "sim2real-cost-center", "Value": "1234"},
        ],
    )

    tags = budgets.list_tags_for_resource(ResourceARN=arn)["ResourceTags"]
    tag_map = {t["Key"]: t["Value"] for t in tags}
    assert tag_map.get("sim2real-owner") == "behavioral-suite", (
        f"expected sim2real-owner=behavioral-suite, got {tag_map.get('sim2real-owner')!r}"
    )
    assert tag_map.get("sim2real-cost-center") == "1234", (
        f"expected sim2real-cost-center=1234, got {tag_map.get('sim2real-cost-center')!r}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
