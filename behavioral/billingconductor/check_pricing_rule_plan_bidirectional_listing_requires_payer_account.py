"""pricing-rule-plan-bidirectional-listing-requires-payer-account."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "pricing-rule-plan-bidirectional-listing-requires-payer-account"
GROUP = "overly-permissive"
SERVICES = ["billingconductor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """From a non-payer account, ListPricingRulesAssociatedToPricingPlan and
    ListPricingPlansAssociatedWithPricingRule on well-formed ARNs both fail with AccessDeniedException
    "Account <id> is not authorized to call <op>. Only payer account is authorized"."""
    bc = ctx.client("billingconductor")
    account_id = _caller_account_id(ctx)
    fake_plan_arn = f"arn:aws:billingconductor::{account_id}:pricingplan/BOGUS00004"
    fake_rule_arn = f"arn:aws:billingconductor::{account_id}:pricingrule/BOGUS00004"

    code_a, msg_a = _error_info(
        lambda: bc.list_pricing_rules_associated_to_pricing_plan(
            PricingPlanArn=fake_plan_arn
        )
    )
    code_b, msg_b = _error_info(
        lambda: bc.list_pricing_plans_associated_with_pricing_rule(
            PricingRuleArn=fake_rule_arn
        )
    )

    assert code_a == "AccessDeniedException", f"unexpected code_a: {code_a} ({msg_a})"
    assert code_b == "AccessDeniedException", f"unexpected code_b: {code_b} ({msg_b})"
    expected_a = f"Account {account_id} is not authorized to call ListPricingRulesAssociatedToPricingPlan. Only payer account is authorized"
    expected_b = f"Account {account_id} is not authorized to call ListPricingPlansAssociatedWithPricingRule. Only payer account is authorized"
    assert msg_a == expected_a, f"unexpected message_a: {msg_a!r}, expected {expected_a!r}"
    assert msg_b == expected_b, f"unexpected message_b: {msg_b!r}, expected {expected_b!r}"


def _caller_account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _error_info(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return (err["Code"], err.get("Message"))
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
