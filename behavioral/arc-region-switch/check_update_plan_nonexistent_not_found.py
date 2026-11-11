"""update-plan-nonexistent-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-plan-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["arc-region-switch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdatePlan on an arn that does not exist returns ResourceNotFoundException, while the
    identical call against a real, just-created plan succeeds (in-file positive control)."""
    arc = ctx.client("arc-region-switch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    dummy_role = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-dummy-role-')}"

    # positive control: UpdatePlan succeeds against a real plan, so the account and
    # credentials are otherwise healthy for this call.
    region_a, region_b = _pick_regions(ctx)
    arn = arc.create_plan(
        name=ctx.unique_name("sim2real-arc-")[:32].rstrip("-"),
        regions=[region_a, region_b],
        recoveryApproach="activePassive",
        primaryRegion=region_a,
        executionRole=dummy_role,
        workflows=[{"workflowTargetAction": "activate"}],
    )["plan"]["arn"]
    ctx.on_cleanup(lambda: arc.delete_plan(arn=arn))

    updated = arc.update_plan(
        arn=arn,
        workflows=[{"workflowTargetAction": "activate"}],
        executionRole=dummy_role,
    )["plan"]
    assert updated["arn"] == arn

    fake_arn = f"arn:aws:arc-region-switch::{account_id}:plan/simnotexist001:def456"
    code, message = _error(
        lambda: arc.update_plan(
            arn=fake_arn,
            workflows=[{"workflowTargetAction": "activate"}],
            executionRole=dummy_role,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Plan not found for ARN: {fake_arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _pick_regions(ctx):
    region_a = ctx.region
    region_b = "us-west-2" if region_a != "us-west-2" else "us-east-1"
    return region_a, region_b


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
