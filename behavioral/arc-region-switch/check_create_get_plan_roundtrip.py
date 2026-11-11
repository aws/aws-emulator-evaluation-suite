"""create-get-plan-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-get-plan-roundtrip"
GROUP = "crud"
SERVICES = ["arc-region-switch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePlan persists every semantic field and GetPlan returns it faithfully."""
    arc = ctx.client("arc-region-switch")
    account_id = _account_id(ctx)
    region_a, region_b = _pick_regions(ctx)
    name = _plan_name(ctx)
    role_arn = _dummy_role_arn(ctx)

    created = arc.create_plan(
        name=name,
        regions=[region_a, region_b],
        recoveryApproach="activePassive",
        primaryRegion=region_a,
        executionRole=role_arn,
        description="sim2real behavioral roundtrip",
        workflows=[
            {"workflowTargetAction": "activate"},
        ],
        tags={"sim2real": CHECK},
    )["plan"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: arc.delete_plan(arn=arn))

    assert created["name"] == name
    assert set(created["regions"]) == {region_a, region_b}
    assert created["recoveryApproach"] == "activePassive"
    assert created["primaryRegion"] == region_a
    assert created["executionRole"] == role_arn
    assert created["owner"] == account_id
    assert f":arc-region-switch::{account_id}:plan/{name}:" in arn

    fetched = arc.get_plan(arn=arn)["plan"]
    assert fetched["arn"] == arn
    assert fetched["name"] == name
    assert set(fetched["regions"]) == {region_a, region_b}
    assert fetched["recoveryApproach"] == "activePassive"
    assert fetched["primaryRegion"] == region_a
    assert fetched["executionRole"] == role_arn
    assert fetched["description"] == "sim2real behavioral roundtrip"
    assert fetched["owner"] == account_id


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _pick_regions(ctx):
    # A plan requires exactly two distinct Regions; us-east-1/us-west-2 are enabled by
    # default in every commercial account, so the fallback needs no opt-in discovery.
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
