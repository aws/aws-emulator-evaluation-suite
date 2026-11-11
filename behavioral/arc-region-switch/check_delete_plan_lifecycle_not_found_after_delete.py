"""delete-plan-lifecycle-not-found-after-delete."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-plan-lifecycle-not-found-after-delete"
GROUP = "state"
SERVICES = ["arc-region-switch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePlan removes the plan; a subsequent GetPlan and a second DeletePlan both 404."""
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
    )["plan"]["arn"]
    ctx.on_cleanup(lambda: _safe_delete(arc, arn))

    # sanity: plan exists before delete
    fetched_arn = arc.get_plan(arn=arn)["plan"]["arn"]
    assert fetched_arn == arn, f"expected GetPlan to return {arn!r} before delete, got {fetched_arn!r}"

    arc.delete_plan(arn=arn)

    code, message = _error(lambda: arc.get_plan(arn=arn))
    assert code == "ResourceNotFoundException", f"expected GetPlan on a deleted plan to raise ResourceNotFoundException, got {code!r}"
    expected = f"Plan not found for ARN: {arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code, message = _error(lambda: arc.delete_plan(arn=arn))
    assert code == "ResourceNotFoundException", f"expected a second DeletePlan to raise ResourceNotFoundException, got {code!r}"
    expected = f"Plan not found for ARN: {arn}"
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


def _safe_delete(arc, arn):
    try:
        arc.delete_plan(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
