"""create-billing-group-invalid-input-still-payer-gated."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-billing-group-invalid-input-still-payer-gated"
GROUP = "overly-permissive"
SERVICES = ["billingconductor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """From a non-payer account, CreateBillingGroup with empty LinkedAccountIds and no PrimaryAccountId fails
    with AccessDeniedException "Account <id> is not authorized to call CreateBillingGroup. Only payer account
    is authorized", not ValidationException: the payer gate runs before field validation."""
    bc = ctx.client("billingconductor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bad_name = ctx.unique_name("sim2real-bc-noprimary-")

    code, message = _error_info(
        lambda: bc.create_billing_group(
            Name=bad_name,
            AccountGrouping={"LinkedAccountIds": []},
            ComputationPreference={
                "PricingPlanArn": "arn:aws:billingconductor::aws:pricingplan/Passthrough"
            },
        )
    )
    assert code == "AccessDeniedException", f"unexpected error code: {code} ({message})"
    expected = f"Account {account_id} is not authorized to call CreateBillingGroup. Only payer account is authorized"
    assert message == expected, f"unexpected message: {message!r}, expected {expected!r}"


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
