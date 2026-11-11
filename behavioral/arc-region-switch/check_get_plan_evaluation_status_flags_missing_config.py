"""get-plan-evaluation-status-flags-missing-config."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-plan-evaluation-status-flags-missing-config"
GROUP = "state"
SERVICES = ["arc-region-switch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A plan with a working execution role and no alarms, triggers or report configuration
    evaluates to `passed` with no warnings. An otherwise-identical plan whose executionRole
    names a role that was never created evaluates to `actionRequired` with a warning naming it."""
    arc = ctx.client("arc-region-switch")
    region_a, region_b = _pick_regions(ctx)

    good_role_arn = _execution_role_arn(ctx)
    broken_role_arn = _unassumable_role_arn(ctx)

    good_arn, good = _create_and_await_healthy_plan(ctx, arc, region_a, region_b, good_role_arn)
    ctx.on_cleanup(lambda: arc.delete_plan(arn=good_arn))

    broken_arn = arc.create_plan(
        name=_plan_name(ctx, "sim2real-arc-bad-"),
        regions=[region_a, region_b],
        recoveryApproach="activePassive",
        primaryRegion=region_a,
        executionRole=broken_role_arn,
        workflows=[{"workflowTargetAction": "activate"}],
    )["plan"]["arn"]
    ctx.on_cleanup(lambda: arc.delete_plan(arn=broken_arn))
    bad = _await_evaluation(ctx, arc, broken_arn)

    assert good["evaluationState"] == "passed", (
        f"expected passed for a plan with a working role and no alarms/triggers/report "
        f"config, got {good['evaluationState']!r} warnings={good['warnings']!r}"
    )
    assert good["warnings"] == [], f"expected no warnings on the healthy plan, got {good['warnings']!r}"

    assert bad["evaluationState"] == "actionRequired", (
        f"expected actionRequired for a plan whose executionRole cannot be assumed, got "
        f"{bad['evaluationState']!r}"
    )
    assert len(bad["warnings"]) > 0, "expected at least one warning for the unassumable-role plan"
    assert any(
        broken_role_arn in w.get("warningMessage", "") for w in bad["warnings"]
    ), f"expected a warning naming the unassumable role {broken_role_arn!r}, got {bad['warnings']!r}"
    assert all(
        w["warningStatus"] == "active" for w in bad["warnings"]
    ), f"a freshly-surfaced warning must be active, got {bad['warnings']!r}"


def _create_and_await_healthy_plan(ctx, arc, region_a, region_b, role_arn):
    """Retries the whole create+evaluate cycle for the working-role plan: a freshly created
    role's trust policy is not always visible yet to arc-region-switch's one-shot AssumeRole
    check inside its first evaluation, which otherwise misreports a working role as unassumable.
    Confirmed against real AWS -- the same role that this loop eventually evaluates `passed`
    was first observed evaluating `actionRequired` with "Failed to assume role" moments after
    creation."""
    left = ctx.time_left()
    deadline = time.monotonic() + (90 if left is None else min(90, left))
    while True:
        arn = arc.create_plan(
            name=_plan_name(ctx, "sim2real-arc-ok-"),
            regions=[region_a, region_b],
            recoveryApproach="activePassive",
            primaryRegion=region_a,
            executionRole=role_arn,
            workflows=[{"workflowTargetAction": "activate"}],
        )["plan"]["arn"]
        evaluated = _await_evaluation(ctx, arc, arn)
        if evaluated["evaluationState"] == "passed":
            return arn, evaluated
        if time.monotonic() >= deadline:
            arc.delete_plan(arn=arn)
            raise AssertionError(
                "plan with a working execution role never evaluated to passed within the "
                f"role-propagation retry budget; last={evaluated!r}"
            )
        arc.delete_plan(arn=arn)
        time.sleep(2)


def _await_evaluation(ctx, arc, plan_arn):
    def _probe():
        from botocore.exceptions import ClientError

        try:
            return arc.get_plan_evaluation_status(planArn=plan_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                # not yet evaluated even once -- treat like pendingEvaluation and keep polling
                return {"evaluationState": "pendingEvaluation", "warnings": []}
            raise

    try:
        return _poll_until(
            _probe,
            lambda r: r["evaluationState"] != "pendingEvaluation",
            timeout_s=150,
            interval_s=5,
        )
    except AssertionError:
        raise AssertionError(
            f"plan {plan_arn} evaluation never left pendingEvaluation within the poll window; "
            "the background evaluator's cadence is undocumented, so this cannot be distinguished "
            "from a faithfully-slow evaluator without a longer budget",
        )


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


def _execution_role_arn(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-arc-exec-")[:64].rstrip("-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "arc-region-switch.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _unassumable_role_arn(ctx):
    # Deliberately never created -- this is the negative control's subject, not a prerequisite:
    # arc-region-switch must be unable to assume it, which a role that does not exist guarantees.
    return f"arn:aws:iam::{_account_id(ctx)}:role/{ctx.unique_name('sim2real-arc-unassumable-')}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
