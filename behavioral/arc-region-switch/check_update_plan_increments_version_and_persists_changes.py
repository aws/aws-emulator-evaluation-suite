"""update-plan-increments-version-and-persists-changes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-plan-increments-version-and-persists-changes"
GROUP = "state"
SERVICES = ["arc-region-switch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePlan persists new description/workflows and bumps plan.version, leaving identity fields untouched."""
    arc = ctx.client("arc-region-switch")
    region_a, region_b = _pick_regions(ctx)
    name = _plan_name(ctx)
    role_arn = _dummy_role_arn(ctx)

    created = arc.create_plan(
        name=name,
        regions=[region_a, region_b],
        recoveryApproach="activePassive",
        primaryRegion=region_a,
        executionRole=role_arn,
        description="before-update",
        workflows=[{"workflowTargetAction": "activate"}],
        tags={"sim2real-behav": "true"},
    )["plan"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: arc.delete_plan(arn=arn))
    version_before = created["version"]

    updated = arc.update_plan(
        arn=arn,
        description="after-update",
        workflows=[
            {"workflowTargetAction": "activate", "workflowTargetRegion": region_a},
            {"workflowTargetAction": "activate", "workflowTargetRegion": region_b},
        ],
        executionRole=role_arn,
    )["plan"]

    assert updated["description"] == "after-update", (
        f"expected description 'after-update' on the UpdatePlan response, got {updated['description']!r}"
    )
    assert len(updated["workflows"]) == 2, (
        f"expected 2 workflows on the UpdatePlan response, got {len(updated['workflows'])}"
    )
    assert updated["version"] != version_before, (
        f"expected version to change from {version_before!r} after UpdatePlan, still {updated['version']!r}"
    )

    refetched = arc.get_plan(arn=arn)["plan"]
    assert refetched["description"] == "after-update", (
        f"expected GetPlan to persist description 'after-update', got {refetched['description']!r}"
    )
    assert len(refetched["workflows"]) == 2, (
        f"expected GetPlan to persist 2 workflows, got {len(refetched['workflows'])}"
    )
    assert refetched["version"] == updated["version"], (
        f"expected GetPlan version {updated['version']!r} to match UpdatePlan response, got {refetched['version']!r}"
    )
    # identity fields set at creation remain unchanged by an update
    assert refetched["name"] == name, f"expected name {name!r} unchanged by UpdatePlan, got {refetched['name']!r}"
    assert set(refetched["regions"]) == {region_a, region_b}, (
        f"expected regions {{region_a, region_b}} unchanged by UpdatePlan, got {refetched['regions']!r}"
    )
    assert refetched["recoveryApproach"] == "activePassive", (
        f"expected recoveryApproach 'activePassive' unchanged by UpdatePlan, got {refetched['recoveryApproach']!r}"
    )
    assert refetched["primaryRegion"] == region_a, (
        f"expected primaryRegion {region_a!r} unchanged by UpdatePlan, got {refetched['primaryRegion']!r}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _pick_regions(ctx):
    # a Region switch plan needs two *distinct real* AWS Regions; the literal fallback
    # is only ever the secondary of the pair, never the (region-pinned) primary under test
    region_a = ctx.region
    region_b = "us-west-2" if region_a != "us-west-2" else "us-east-1"
    return region_a, region_b


def _plan_name(ctx, prefix="sim2real-arc-"):
    return ctx.unique_name(prefix)[:32].rstrip("-")


def _dummy_role_arn(ctx):
    return f"arn:aws:iam::{_account_id(ctx)}:role/{ctx.unique_name('sim2real-dummy-role-')}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
