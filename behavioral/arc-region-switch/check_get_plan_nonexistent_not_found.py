"""get-plan-nonexistent-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-plan-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["arc-region-switch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetPlan on a real plan succeeds; GetPlan on a well-formed but never-created arn (derived
    from the real one by perturbing only the plan name, so it stays in the caller's own account
    scope) returns ResourceNotFoundException."""
    arc = ctx.client("arc-region-switch")
    region_a, region_b = _pick_regions(ctx)
    name = _plan_name(ctx)
    role_arn = _dummy_role_arn(ctx)

    arn = arc.create_plan(
        name=name,
        regions=[region_a, region_b],
        recoveryApproach="activePassive",
        primaryRegion=region_a,
        executionRole=role_arn,
        workflows=[{"workflowTargetAction": "activate"}],
        tags={"sim2real": CHECK},
    )["plan"]["arn"]
    ctx.on_cleanup(lambda: arc.delete_plan(arn=arn))

    # positive control: the real plan is actually there
    fetched_arn = arc.get_plan(arn=arn)["plan"]["arn"]
    assert fetched_arn == arn, f"expected GetPlan to echo {arn!r}, got {fetched_arn!r}"

    bogus_arn = arn.replace(f"plan/{name}:", f"plan/{name}-absent:")
    assert bogus_arn != arn, f"perturbation produced no change on {arn!r}"

    code, message = _error(lambda: arc.get_plan(arn=bogus_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Plan not found for ARN: {bogus_arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
