"""list-recovery-plans-pagination-returns-all-created-once."""

from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-recovery-plans-pagination-returns-all-created-once"
GROUP = "recovery-plans"
SERVICES = ["drs"]


@tags(
    "requires:drs-initialized",
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """ListRecoveryPlans, paginated one item per page, surfaces every plan this check created
    exactly once, with no drop and no duplicate across page boundaries."""
    drs = ctx.client("drs")
    names = [ctx.unique_name(f"sim2real-behav-drs-plan-{i}-") for i in range(3)]
    arns = []
    for name in names:
        created = drs.create_recovery_plan(name=name)["recoveryPlan"]
        arns.append(created["recoveryPlanArn"])
        ctx.on_cleanup(
            lambda arn=created["recoveryPlanArn"]: drs.delete_recovery_plan(recoveryPlanArn=arn)
        )

    seen: list[str] = []
    pages = drs.get_paginator("list_recovery_plans").paginate(PaginationConfig={"PageSize": 1})
    for page in pages:
        seen.extend(p["recoveryPlanArn"] for p in page["recoveryPlans"])

    for arn in arns:
        count = seen.count(arn)
        assert count == 1, f"plan {arn!r} appeared {count} time(s) across pages, expected exactly 1"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
