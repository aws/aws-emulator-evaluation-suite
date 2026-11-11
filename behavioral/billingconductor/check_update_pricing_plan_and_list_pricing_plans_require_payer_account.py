"""update-pricing-plan-and-list-pricing-plans-require-payer-account."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-pricing-plan-and-list-pricing-plans-require-payer-account"
GROUP = "overly-permissive"
SERVICES = ["billingconductor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """From a non-payer account, UpdatePricingPlan on a nonexistent plan and ListPricingPlans both fail with
    AccessDeniedException "Account <id> is not authorized to call <op>. Only payer account is authorized",
    while TagResource on the same plan arn fails with NotFoundException "Resource was not found"."""
    bc = ctx.client("billingconductor")
    account_id = _caller_account_id(ctx)
    fake_plan_arn = f"arn:aws:billingconductor::{account_id}:pricingplan/BOGUS0000B"

    control_code, control_msg = _error_info(
        lambda: bc.tag_resource(ResourceArn=fake_plan_arn, Tags={"env": "sim2real"})
    )
    assert control_code == "NotFoundException", (
        f"positive control TagResource: expected NotFoundException, got {control_code} ({control_msg})"
    )
    assert control_msg == "Resource was not found", (
        f"positive control TagResource: unexpected message: {control_msg!r}"
    )

    code_a, msg_a = _error_info(
        lambda: bc.update_pricing_plan(Arn=fake_plan_arn, Description="updated")
    )
    assert code_a == "AccessDeniedException", f"UpdatePricingPlan: unexpected code: {code_a} ({msg_a})"
    expected_a = f"Account {account_id} is not authorized to call UpdatePricingPlan. Only payer account is authorized"
    assert msg_a == expected_a, f"UpdatePricingPlan: unexpected message: {msg_a!r}, expected {expected_a!r}"

    code_b, msg_b = _error_info(lambda: bc.list_pricing_plans(MaxResults=5))
    assert code_b == "AccessDeniedException", f"ListPricingPlans: unexpected code: {code_b} ({msg_b})"
    expected_b = f"Account {account_id} is not authorized to call ListPricingPlans. Only payer account is authorized"
    assert msg_b == expected_b, f"ListPricingPlans: unexpected message: {msg_b!r}, expected {expected_b!r}"


def _caller_account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _error_info(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return (err["Code"], err.get("Message"))
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
