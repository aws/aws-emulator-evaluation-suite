"""update-operations-require-payer-account."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-operations-require-payer-account"
GROUP = "overly-permissive"
SERVICES = ["billingconductor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """From a non-payer account, UpdatePricingRule, UpdateBillingGroup and UpdateCustomLineItem on well-formed
    but nonexistent ARNs each fail with AccessDeniedException "Account <id> is not authorized to call <op>.
    Only payer account is authorized", not ResourceNotFoundException."""
    bc = ctx.client("billingconductor")
    account_id = _caller_account_id(ctx)

    checks = {
        "UpdatePricingRule": lambda: bc.update_pricing_rule(
            Arn=f"arn:aws:billingconductor::{account_id}:pricingrule/BOGUS00008",
            Description="updated",
        ),
        "UpdateBillingGroup": lambda: bc.update_billing_group(
            Arn=f"arn:aws:billingconductor::{account_id}:billinggroup/BOGUS00008",
            Description="updated",
        ),
        "UpdateCustomLineItem": lambda: bc.update_custom_line_item(
            Arn=f"arn:aws:billingconductor::{account_id}:customlineitem/BOGUS00008",
            Description="updated",
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
