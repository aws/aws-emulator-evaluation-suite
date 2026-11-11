"""associate-and-disassociate-pricing-rules-require-payer-account."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "associate-and-disassociate-pricing-rules-require-payer-account"
GROUP = "overly-permissive"
SERVICES = ["billingconductor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """From a non-payer account, 6 concurrent AssociatePricingRules and 6 concurrent DisassociatePricingRules
    calls on well-formed but nonexistent plan/rule ARNs all fail with AccessDeniedException "Account <id> is
    not authorized to call ... Only payer account is authorized", with no call succeeding."""
    from botocore.exceptions import ClientError
    from concurrent.futures import ThreadPoolExecutor, as_completed

    bc = ctx.client("billingconductor")
    account_id = _caller_account_id(ctx)
    fake_plan_arn = f"arn:aws:billingconductor::{account_id}:pricingplan/BOGUS00003"
    fake_rule_arn = f"arn:aws:billingconductor::{account_id}:pricingrule/BOGUS00003"
    racers = 6

    def _race(op):
        def _attempt(_i):
            try:
                op()
                return ("ok", None)
            except ClientError as exc:
                return ("error", (exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")))

        with ThreadPoolExecutor(max_workers=racers) as pool:
            futures = [pool.submit(_attempt, i) for i in range(racers)]
            return [f.result() for f in as_completed(futures)]

    results_a = _race(
        lambda: bc.associate_pricing_rules(Arn=fake_plan_arn, PricingRuleArns=[fake_rule_arn])
    )
    assert len(results_a) == racers, f"AssociatePricingRules: expected {racers} results, got {results_a}"
    assert all(status == "error" for status, _ in results_a), (
        f"AssociatePricingRules: expected zero winners across {racers} racers, got {results_a}"
    )
    assert all(code == "AccessDeniedException" for _, (code, _message) in results_a), (
        f"AssociatePricingRules: expected every racer denied with AccessDeniedException, got {results_a}"
    )
    assert all(message == _payer_only_denial(account_id, "AssociatePricingRules")
               for _, (_code, message) in results_a), (
        f"AssociatePricingRules: expected the payer-account-only denial message, got {results_a}"
    )

    results_b = _race(
        lambda: bc.disassociate_pricing_rules(Arn=fake_plan_arn, PricingRuleArns=[fake_rule_arn])
    )
    assert len(results_b) == racers, f"DisassociatePricingRules: expected {racers} results, got {results_b}"
    assert all(status == "error" for status, _ in results_b), (
        f"DisassociatePricingRules: expected zero winners across {racers} racers, got {results_b}"
    )
    assert all(code == "AccessDeniedException" for _, (code, _message) in results_b), (
        f"DisassociatePricingRules: expected every racer denied with AccessDeniedException, got {results_b}"
    )
    assert all(message == _payer_only_denial(account_id, "DisassociatePricingRules")
               for _, (_code, message) in results_b), (
        f"DisassociatePricingRules: expected the payer-account-only denial message, got {results_b}"
    )


def _payer_only_denial(account_id, operation):
    """The exact AccessDeniedException message billingconductor returns to a non-payer caller."""
    return f"Account {account_id} is not authorized to call {operation}. Only payer account is authorized"


def _caller_account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
