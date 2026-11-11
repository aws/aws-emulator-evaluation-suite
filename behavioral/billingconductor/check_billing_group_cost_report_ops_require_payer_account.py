"""billing-group-cost-report-ops-require-payer-account."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "billing-group-cost-report-ops-require-payer-account"
GROUP = "overly-permissive"
SERVICES = ["billingconductor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """From a non-payer account, ListBillingGroupCostReports and GetBillingGroupCostReport on a nonexistent
    billing group fail with AccessDeniedException "Account <id> is not authorized to call <op>. Only payer
    account is authorized", not an empty page or a zeroed report."""
    bc = ctx.client("billingconductor")
    account_id = _caller_account_id(ctx)
    fake_bg_arn = f"arn:aws:billingconductor::{account_id}:billinggroup/BOGUS00009"

    code_a, msg_a = _error_info(lambda: bc.list_billing_group_cost_reports(MaxResults=5))
    assert code_a == "AccessDeniedException", (
        f"ListBillingGroupCostReports: unexpected code: {code_a} ({msg_a})"
    )
    expected_a = f"Account {account_id} is not authorized to call ListBillingGroupCostReports. Only payer account is authorized"
    assert msg_a == expected_a, (
        f"ListBillingGroupCostReports: unexpected message: {msg_a!r}, expected {expected_a!r}"
    )

    code_b, msg_b = _error_info(lambda: bc.get_billing_group_cost_report(Arn=fake_bg_arn))
    assert code_b == "AccessDeniedException", (
        f"GetBillingGroupCostReport: unexpected code: {code_b} ({msg_b})"
    )
    expected_b = f"Account {account_id} is not authorized to call GetBillingGroupCostReport. Only payer account is authorized"
    assert msg_b == expected_b, (
        f"GetBillingGroupCostReport: unexpected message: {msg_b!r}, expected {expected_b!r}"
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
