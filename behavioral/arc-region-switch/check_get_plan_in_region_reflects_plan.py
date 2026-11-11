"""get-plan-in-region-reflects-plan."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-plan-in-region-reflects-plan"
GROUP = "state"
SERVICES = ["arc-region-switch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPlanInRegion (the regional data plane) eventually reflects a plan created via the control
    plane, in a Region that is one of the plan's own two Regions."""
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
        workflows=[{"workflowTargetAction": "activate"}],
        tags={"env": "sim2real-behav"},
    )["plan"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: arc.delete_plan(arn=arn))

    # ctx's arc-region-switch client targets ctx.region == region_a, one of the plan's own
    # Regions, so it must become visible on the regional data plane (replication lag possible).
    in_region = _poll_until(
        lambda: _get_plan_in_region_or_none(arc, arn),
        lambda r: r is not None,
        timeout_s=60,
    )
    assert in_region["arn"] == arn, f"expected arn {arn!r}, got {in_region['arn']!r}"
    assert in_region["name"] == name, f"expected name {name!r}, got {in_region['name']!r}"
    assert set(in_region["regions"]) == {region_a, region_b}, (
        f"expected regions {{region_a, region_b}}, got {in_region['regions']!r}"
    )
    assert in_region["recoveryApproach"] == "activePassive", (
        f"expected recoveryApproach 'activePassive', got {in_region['recoveryApproach']!r}"
    )
    assert in_region["primaryRegion"] == region_a, (
        f"expected primaryRegion {region_a!r}, got {in_region['primaryRegion']!r}"
    )
    assert in_region["executionRole"] == role_arn, (
        f"expected executionRole {role_arn!r}, got {in_region['executionRole']!r}"
    )
    assert in_region["owner"] == account_id, (
        f"expected owner {account_id!r}, got {in_region['owner']!r}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _pick_regions(ctx):
    # arc-region-switch plans require two distinct Regions; region_b is not itself
    # significant to this check, only that it differs from ctx.region, so any two
    # globally-available Regions serve.
    region_a = ctx.region
    region_b = "us-west-2" if region_a != "us-west-2" else "us-east-1"
    return region_a, region_b


def _plan_name(ctx, prefix="sim2real-arc-"):
    return ctx.unique_name(prefix)[:32].rstrip("-")


def _dummy_role_arn(ctx):
    return f"arn:aws:iam::{_account_id(ctx)}:role/{ctx.unique_name('sim2real-dummy-role-')}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _get_plan_in_region_or_none(arc, arn):
    from botocore.exceptions import ClientError

    try:
        return arc.get_plan_in_region(arn=arn)["plan"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
