"""delete-operations-require-payer-account."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-operations-require-payer-account"
GROUP = "overly-permissive"
SERVICES = ["billingconductor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """From a non-payer account, DeletePricingRule, DeletePricingPlan, DeleteBillingGroup and DeleteCustomLineItem
    on well-formed but nonexistent ARNs each fail with AccessDeniedException "Account <id> is not authorized to
    call <op>. Only payer account is authorized", not ResourceNotFoundException."""
    bc = ctx.client("billingconductor")
    account_id = _caller_account_id(ctx)

    checks = {
        "DeletePricingRule": lambda: bc.delete_pricing_rule(
            Arn=f"arn:aws:billingconductor::{account_id}:pricingrule/BOGUS00002"
        ),
        "DeletePricingPlan": lambda: bc.delete_pricing_plan(
            Arn=f"arn:aws:billingconductor::{account_id}:pricingplan/BOGUS00002"
        ),
        "DeleteBillingGroup": lambda: bc.delete_billing_group(
            Arn=f"arn:aws:billingconductor::{account_id}:billinggroup/BOGUS00002"
        ),
        "DeleteCustomLineItem": lambda: bc.delete_custom_line_item(
            Arn=f"arn:aws:billingconductor::{account_id}:customlineitem/BOGUS00002"
        ),
    }

    for op_name, call in checks.items():
        code, message = _error_info(call)
        assert code == "AccessDeniedException", (
            f"{op_name}: unexpected error code: {code} ({message})"
        )
        expected = f"Account {account_id} is not authorized to call {op_name}. Only payer account is authorized"
        assert message == expected, (
            f"{op_name}: unexpected message: {message!r}, expected {expected!r}"
        )


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
