"""create-billing-group-requires-payer-account."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-billing-group-requires-payer-account"
GROUP = "overly-permissive"
SERVICES = ["billingconductor"]

_PASSTHROUGH_PLAN_ARN = "arn:aws:billingconductor::aws:pricingplan/Passthrough"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """From a non-payer account, CreateBillingGroup fails with AccessDeniedException "Account <id> is not
    authorized to call CreateBillingGroup. Only payer account is authorized", and ListBillingGroups for the
    name either fails with the same denial for ListBillingGroups or returns no billing group."""
    bc = ctx.client("billingconductor")
    name = ctx.unique_name("sim2real-bc-bg-")
    placeholder_account_id = "111111111111"
    name_filter = {"Filters": {"Names": [{"SearchOption": "STARTS_WITH", "SearchValue": name}]}}

    identity = ctx.client("sts").get_caller_identity()
    assert identity.get("Account"), "STS GetCallerIdentity did not resolve an account -- credentials are not usable at all"

    code, message, resp = _attempt(
        lambda: bc.create_billing_group(
            Name=name,
            AccountGrouping={"LinkedAccountIds": [placeholder_account_id]},
            ComputationPreference={"PricingPlanArn": _PASSTHROUGH_PLAN_ARN},
            PrimaryAccountId=placeholder_account_id,
            Tags={"sim2real": "true"},
        )
    )
    if resp is not None:
        ctx.on_cleanup(lambda: bc.delete_billing_group(Arn=resp["Arn"]))
    assert code == "AccessDeniedException", f"unexpected error code: {code} ({message})"
    expected = f"Account {identity["Account"]} is not authorized to call CreateBillingGroup. Only payer account is authorized"
    assert message == expected, f"unexpected message: {message!r}, expected {expected!r}"

    list_code, list_message, list_resp = _attempt(lambda: bc.list_billing_groups(**name_filter))
    if list_resp is not None:
        # The read surface turned out not to be payer-gated after all: fall back to an
        # independent proof that the denied create left no trace.
        assert list_resp["BillingGroups"] == [], (
            f"billing group {name} is visible via ListBillingGroups despite the "
            f"AccessDeniedException on create: {list_resp['BillingGroups']}"
        )
    else:
        assert list_code == "AccessDeniedException", f"unexpected error code: {list_code} ({list_message})"
        expected_list = f"Account {identity["Account"]} is not authorized to call ListBillingGroups. Only payer account is authorized"
        assert list_message == expected_list, (
            f"unexpected message: {list_message!r}, expected {expected_list!r}"
        )


def _attempt(fn):
    """Run fn() and return (code, message, None) on a ClientError, else (None, None, response)."""
    from botocore.exceptions import ClientError

    try:
        return (None, None, fn())
    except ClientError as exc:
        err = exc.response["Error"]
        return (err["Code"], err.get("Message"), None)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
