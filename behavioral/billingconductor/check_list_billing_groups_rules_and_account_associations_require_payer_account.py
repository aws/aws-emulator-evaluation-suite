"""list-billing-groups-rules-and-account-associations-require-payer-account."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-billing-groups-rules-and-account-associations-require-payer-account"
GROUP = "overly-permissive"
SERVICES = ["billingconductor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """From a non-payer account, ListBillingGroups, ListPricingRules and ListAccountAssociations each fail with
    AccessDeniedException "Account <id> is not authorized to call <op>. Only payer account is authorized",
    not an empty page."""
    bc = ctx.client("billingconductor")
    account_id = _caller_account_id(ctx)
    fake_bg_arn = f"arn:aws:billingconductor::{account_id}:billinggroup/BOGUS0000C"

    code_a, msg_a = _error_info(lambda: bc.list_billing_groups(MaxResults=5))
    assert code_a == "AccessDeniedException", f"ListBillingGroups: unexpected code: {code_a} ({msg_a})"
    expected_a = f"Account {account_id} is not authorized to call ListBillingGroups. Only payer account is authorized"
    assert msg_a == expected_a, (
        f"ListBillingGroups: unexpected message: {msg_a!r}, expected {expected_a!r}"
    )

    code_b, msg_b = _error_info(lambda: bc.list_pricing_rules(MaxResults=5))
    assert code_b == "AccessDeniedException", f"ListPricingRules: unexpected code: {code_b} ({msg_b})"
    expected_b = f"Account {account_id} is not authorized to call ListPricingRules. Only payer account is authorized"
    assert msg_b == expected_b, (
        f"ListPricingRules: unexpected message: {msg_b!r}, expected {expected_b!r}"
    )

    code_c, msg_c = _error_info(
        lambda: bc.list_account_associations(Filters={"Association": fake_bg_arn})
    )
    assert code_c == "AccessDeniedException", (
        f"ListAccountAssociations: unexpected code: {code_c} ({msg_c})"
    )
    expected_c = f"Account {account_id} is not authorized to call ListAccountAssociations. Only payer account is authorized"
    assert msg_c == expected_c, (
        f"ListAccountAssociations: unexpected message: {msg_c!r}, expected {expected_c!r}"
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
