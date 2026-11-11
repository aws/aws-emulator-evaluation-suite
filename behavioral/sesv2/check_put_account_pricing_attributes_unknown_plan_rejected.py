"""put-account-pricing-attributes-unknown-plan-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-account-pricing-attributes-unknown-plan-rejected"
GROUP = "negative-classes"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ses-account")
def run(ctx) -> None:
    """PutAccountPricingAttributes with a plan outside the PricingPlan enum is rejected and leaves
    the account's current and next plan exactly as GetAccount reported them before the call."""
    ses = ctx.client("sesv2")
    raw = ctx.client(
        "sesv2", config=Config(parameter_validation=False, retries={"max_attempts": 1})
    )
    before = ses.get_account().get("PricingAttributes", {})

    code, message = _error(lambda: raw.put_account_pricing_attributes(Plan="PLATINUM"))
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}: {message!r}"
    expected = (
        "1 validation error detected: Value at 'plan' failed to satisfy constraint: "
        "Member must satisfy enum value set: [ENTERPRISE, ESSENTIALS, PRO, NONE]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = ses.get_account().get("PricingAttributes", {})
    assert after.get("CurrentPlan") == before.get("CurrentPlan"), (
        f"the rejected call moved CurrentPlan from {before.get('CurrentPlan')!r} "
        f"to {after.get('CurrentPlan')!r}"
    )
    assert after.get("NextPlan") == before.get("NextPlan"), (
        f"the rejected call moved NextPlan from {before.get('NextPlan')!r} "
        f"to {after.get('NextPlan')!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
