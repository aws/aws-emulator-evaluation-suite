"""create-plan-invalid-region-count-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-plan-invalid-region-count-rejected"
GROUP = "overly-permissive"
SERVICES = ["arc-region-switch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePlan requires two DISTINCT Regions; supplying the same Region twice is rejected and
    creates nothing, while the same request with two distinct Regions succeeds (in-file positive
    control)."""
    arc = ctx.client("arc-region-switch")
    region_a, region_b = _pick_regions(ctx)
    role_arn = _dummy_role_arn(ctx)
    bad_name = _plan_name(ctx, "sim2real-arc-bad-")

    code, message = _error(
        lambda: arc.create_plan(
            name=bad_name,
            regions=[region_a, region_a],
            recoveryApproach="activePassive",
            primaryRegion=region_a,
            executionRole=role_arn,
            workflows=[{"workflowTargetAction": "activate"}],
        )
    )
    assert code == "ValidationException", (
        f"CreatePlan with a duplicated Region ({region_a!r} twice) should be rejected with "
        f"ValidationException, got {code!r}"
    )
    expected = "There are duplicate regions defined in the plan. Please remove the duplicated regions. "
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no plan with that name exists
    leaked = _find_plan_by_name(arc, bad_name)
    assert leaked is None, (
        f"CreatePlan was rejected but a plan named {bad_name!r} exists anyway: {leaked!r}"
    )

    # positive control: the identical request with two distinct Regions succeeds
    good_name = _plan_name(ctx, "sim2real-arc-ok-")
    good_arn = arc.create_plan(
        name=good_name,
        regions=[region_a, region_b],
        recoveryApproach="activePassive",
        primaryRegion=region_a,
        executionRole=role_arn,
        workflows=[{"workflowTargetAction": "activate"}],
    )["plan"]["arn"]
    ctx.on_cleanup(lambda: arc.delete_plan(arn=good_arn))
    fetched_name = arc.get_plan(arn=good_arn)["plan"]["name"]
    assert fetched_name == good_name, (
        f"the positive control plan should be retrievable by its own arn with name "
        f"{good_name!r}, got {fetched_name!r}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _pick_regions(ctx):
    region_a = ctx.region
    region_b = "us-west-2" if region_a != "us-west-2" else "us-east-1"
    return region_a, region_b


def _plan_name(ctx, prefix="sim2real-arc-"):
    return ctx.unique_name(prefix)[:32].rstrip("-")


def _dummy_role_arn(ctx):
    return f"arn:aws:iam::{_account_id(ctx)}:role/{ctx.unique_name('sim2real-dummy-role-')}"


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        error = e.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _find_plan_by_name(arc, name):
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = arc.list_plans(**kwargs)
        for plan in resp.get("plans", []):
            if plan["name"] == name:
                return plan
        next_token = resp.get("nextToken")
        if not next_token:
            return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
