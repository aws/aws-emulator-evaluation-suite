"""update-rule-retention-period-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-rule-retention-period-persists"
GROUP = "state"
SERVICES = ["rbin"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateRule's new RetentionPeriod and Description persist and are visible on a
    subsequent GetRule."""
    rbin = ctx.client("rbin")

    rule_id = rbin.create_rule(
        ResourceType="EBS_SNAPSHOT",
        RetentionPeriod={"RetentionPeriodValue": 5, "RetentionPeriodUnit": "DAYS"},
        Description="initial description",
    )["Identifier"]
    ctx.on_cleanup(lambda: rbin.delete_rule(Identifier=rule_id))

    updated = rbin.update_rule(
        Identifier=rule_id,
        RetentionPeriod={"RetentionPeriodValue": 42, "RetentionPeriodUnit": "DAYS"},
        Description="updated description",
    )
    assert updated["RetentionPeriod"] == {"RetentionPeriodValue": 42, "RetentionPeriodUnit": "DAYS"}, (
        f"expected UpdateRule to echo RetentionPeriodValue=42 DAYS, got {updated['RetentionPeriod']!r}"
    )
    assert updated["Description"] == "updated description", (
        f"expected UpdateRule to echo the new description, got {updated['Description']!r}"
    )

    fetched = rbin.get_rule(Identifier=rule_id)
    assert fetched["RetentionPeriod"] == {"RetentionPeriodValue": 42, "RetentionPeriodUnit": "DAYS"}, (
        f"expected GetRule to persist RetentionPeriodValue=42 DAYS after update, got {fetched['RetentionPeriod']!r}"
    )
    assert fetched["Description"] == "updated description", (
        f"expected GetRule to persist the updated description, got {fetched['Description']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
