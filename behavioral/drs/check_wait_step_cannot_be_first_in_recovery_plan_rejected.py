"""wait-step-cannot-be-first-in-recovery-plan-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "wait-step-cannot-be-first-in-recovery-plan-rejected"
GROUP = "overly-permissive"
SERVICES = ["drs"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "plane:control",
    "requires:drs-initialized",
)
def run(ctx) -> None:
    """CreateRecoveryPlanStep refuses a WAIT-type step as the first step of a recovery plan with
    ValidationException and creates nothing, while the plan itself is left usable.
    """
    drs = ctx.client("drs")
    name = ctx.unique_name("sim2real-drs-rp-waitfirst-")

    created = drs.create_recovery_plan(name=name)["recoveryPlan"]
    rp_arn = created["recoveryPlanArn"]
    ctx.on_cleanup(lambda: _delete_plan(drs, rp_arn))

    code, message = _expect_rejected(
        lambda: drs.create_recovery_plan_step(
            recoveryPlanArn=rp_arn,
            stepName="sim2real-wait-step",
            stepOrder=1,
            configuration={"waitStepConfiguration": {"waitDurationMinutes": 5}},
        )
    )
    assert code == "ValidationException", (
        f"a WAIT step as the first step of a recovery plan must raise ValidationException, got {code!r}"
    )
    assert message == "A WAIT step cannot be the first step in a recovery plan.", (
        f"expected the exact documented refusal message, got {message!r}"
    )

    steps = drs.list_recovery_plan_steps(recoveryPlanArn=rp_arn)["recoveryPlanSteps"]
    assert steps == [], (
        f"the refused CreateRecoveryPlanStep must not have created a step, got {steps!r}"
    )

    # Positive control: the plan itself is unharmed by the refused step and still answers.
    fetched = drs.get_recovery_plan(recoveryPlanArn=rp_arn)["recoveryPlan"]
    assert fetched["name"] == name, (
        f"the recovery plan must remain readable and unchanged after the refused step, "
        f"got name {fetched.get('name')!r}"
    )


def _expect_rejected(fn):
    try:
        result = fn()
        raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")


def _delete_plan(drs, rp_arn: str) -> None:
    try:
        drs.delete_recovery_plan(recoveryPlanArn=rp_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
