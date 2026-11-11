"""create-pricing-plan-nonexistent-pricing-rule-arns-still-payer-gated."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-pricing-plan-nonexistent-pricing-rule-arns-still-payer-gated"
GROUP = "overly-permissive"
SERVICES = ["billingconductor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """From a non-payer account, CreatePricingPlan naming a nonexistent pricing rule fails with
    AccessDeniedException "Account <id> is not authorized to call CreatePricingPlan. Only payer account is
    authorized", not ResourceNotFoundException, and ListPricingPlans is denied the same way or omits the name."""
    bc = ctx.client("billingconductor")
    account_id = _caller_account_id(ctx)
    bad_name = ctx.unique_name("sim2real-bc-badplan-")
    bogus_rule_arn = f"arn:aws:billingconductor::{account_id}:pricingrule/BOGUS00001"

    created = {}

    def _create():
        resp = bc.create_pricing_plan(
            Name=bad_name,
            PricingRuleArns=[bogus_rule_arn],
            Tags={"sim2real": "true"},
        )
        created["arn"] = resp["Arn"]

    ctx.on_cleanup(lambda: bc.delete_pricing_plan(Arn=created["arn"]) if created.get("arn") else None)

    code, message = _error_info(_create)
    assert code == "AccessDeniedException", f"unexpected error code: {code} ({message})"
    expected = f"Account {account_id} is not authorized to call CreatePricingPlan. Only payer account is authorized"
    assert message == expected, f"unexpected message: {message!r}, expected {expected!r}"

    list_code, list_message, list_names = _list_or_denied(bc)
    if list_code is not None:
        assert list_code == "AccessDeniedException", (
            f"create was denied but the independent ListPricingPlans read failed "
            f"differently: {list_code} ({list_message})"
        )
        expected_list = f"Account {account_id} is not authorized to call ListPricingPlans. Only payer account is authorized"
        assert list_message == expected_list, (
            f"ListPricingPlans: unexpected message: {list_message!r}, expected {expected_list!r}"
        )
    else:
        assert bad_name not in list_names, (
            f"plan {bad_name} unexpectedly visible in ListPricingPlans after a denied create"
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


def _list_or_denied(bc):
    from botocore.exceptions import ClientError

    try:
        names = [p["Name"] for p in bc.list_pricing_plans().get("PricingPlans", [])]
        return (None, None, names)
    except ClientError as exc:
        err = exc.response["Error"]
        return (err["Code"], err.get("Message"), None)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
