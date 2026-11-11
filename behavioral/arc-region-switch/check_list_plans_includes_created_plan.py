"""list-plans-includes-created-plan."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-plans-includes-created-plan"
GROUP = "crud"
SERVICES = ["arc-region-switch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPlans (account-wide control plane view) surfaces a just-created plan with matching fields."""
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
        workflows=[{"workflowTargetAction": "activate"}],
        tags={"env": "sim2real-behav"},
    )["plan"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: arc.delete_plan(arn=arn))

    match = _find_plan(arc, arn)
    assert match is not None, f"plan {arn} not found in ListPlans"
    assert match["name"] == name, f"expected name {name!r}, got {match['name']!r}"
    assert set(match["regions"]) == {region_a, region_b}, (
        f"expected regions {{region_a, region_b}}, got {match['regions']!r}"
    )
    assert match["recoveryApproach"] == "activePassive", (
        f"expected recoveryApproach 'activePassive', got {match['recoveryApproach']!r}"
    )
    assert match["primaryRegion"] == region_a, (
        f"expected primaryRegion {region_a!r}, got {match['primaryRegion']!r}"
    )
    assert match["executionRole"] == role_arn, (
        f"expected executionRole {role_arn!r}, got {match['executionRole']!r}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _pick_regions(ctx):
    # arc-region-switch plans are inherently multi-region: a second, distinct region is
    # part of the resource under test, not an incidental pin, and there is no API to
    # discover "some other region" from the account.
    region_a = ctx.region
    region_b = "us-west-2" if region_a != "us-west-2" else "us-east-1"
    return region_a, region_b


def _plan_name(ctx, prefix="sim2real-arc-"):
    return ctx.unique_name(prefix)[:32].rstrip("-")


def _dummy_role_arn(ctx):
    return f"arn:aws:iam::{_account_id(ctx)}:role/{ctx.unique_name('sim2real-dummy-role-')}"


def _find_plan(arc, arn):
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = arc.list_plans(**kwargs)
        for plan in resp.get("plans", []):
            if plan["arn"] == arn:
                return plan
        next_token = resp.get("nextToken")
        if not next_token:
            return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
