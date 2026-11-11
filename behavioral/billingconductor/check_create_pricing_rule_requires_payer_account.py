"""create-pricing-rule-requires-payer-account."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-pricing-rule-requires-payer-account"
GROUP = "overly-permissive"
SERVICES = ["billingconductor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """From a non-payer account, CreatePricingRule fails with AccessDeniedException "Account <id> is not
    authorized to call CreatePricingRule. Only payer account is authorized"."""
    bc = ctx.client("billingconductor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-bc-rule-")

    code, message = _error_info(
        lambda: bc.create_pricing_rule(
            Name=name,
            Description="markup rule v1",
            Scope="GLOBAL",
            Type="MARKUP",
            ModifierPercentage=10.0,
        )
    )
    assert code == "AccessDeniedException", f"unexpected error code: {code} ({message})"
    expected = f"Account {account_id} is not authorized to call CreatePricingRule. Only payer account is authorized"
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
