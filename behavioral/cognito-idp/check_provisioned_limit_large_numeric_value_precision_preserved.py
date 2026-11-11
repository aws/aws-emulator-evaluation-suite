"""provisioned-limit-large-numeric-value-precision-preserved."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "provisioned-limit-large-numeric-value-precision-preserved"
GROUP = "representation"
SERVICES = ["cognito-idp"]

_LIMIT_DEFINITION = {"LimitClass": "API_CATEGORY", "Attributes": {"Category": "UserAuthentication"}}

# Far beyond any plausible account-level max RPS for this category.
_ABSURDLY_ABOVE = 2_000_000_000


@tags("axis:rejection", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cognito-idp-provisioned-limits")
def run(ctx) -> None:
    """GetProvisionedLimit returns integer values for the category; UpdateProvisionedLimit fails with
    InvalidParameterException for the current value and one below the free limit and with
    ServiceQuotaExceededException above the ceiling, and none of them moves the value."""
    cognito = ctx.client("cognito-idp")

    baseline = cognito.get_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION)["Limit"]
    original_value = baseline["ProvisionedLimitValue"]
    free_value = baseline["FreeLimitValue"]
    assert isinstance(original_value, int)
    assert isinstance(free_value, int)
    assert baseline["LimitDefinition"] == _LIMIT_DEFINITION

    # Re-applying the value already in effect is itself invalid -- an idempotency
    # guard distinct from the range check below. It holds once the value is provisioned.
    _write_current(cognito, original_value)
    code, message = _error(
        lambda: cognito.update_provisioned_limit(
            LimitDefinition=_LIMIT_DEFINITION, RequestedLimitValue=original_value
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException for the unchanged value, got {code!r}"
    assert message == _SAME_VALUE, message
    after_noop = cognito.get_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION)["Limit"]
    assert after_noop["ProvisionedLimitValue"] == original_value, (
        f"the provisioned limit changed to {after_noop['ProvisionedLimitValue']!r} even though "
        "re-applying the unchanged value was rejected"
    )

    # Below the floor: always invalid by contract, regardless of this account's
    # current headroom.
    below = free_value - 1
    code, _ = _error(
        lambda: cognito.update_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION, RequestedLimitValue=below)
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException for {below!r}, got {code!r}"
    after_below = cognito.get_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION)["Limit"]
    assert after_below["ProvisionedLimitValue"] == original_value, (
        f"the provisioned limit changed to {after_below['ProvisionedLimitValue']!r} even though "
        f"RequestedLimitValue={below!r} was rejected"
    )

    # Above the ceiling: absurdly beyond any plausible account-level max.
    above = original_value + _ABSURDLY_ABOVE
    code, message = _error(
        lambda: cognito.update_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION, RequestedLimitValue=above)
    )
    assert code == "ServiceQuotaExceededException", f"expected ServiceQuotaExceededException for {above!r}, got {code!r}"
    # The ceiling is the account's Service Quotas value, which no read here returns.
    assert message.startswith(f"Requested value {above} exceeds Service Quota ceiling of "), message
    after_above = cognito.get_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION)["Limit"]
    assert after_above["ProvisionedLimitValue"] == original_value, (
        f"the provisioned limit changed to {after_above['ProvisionedLimitValue']!r} even though "
        f"RequestedLimitValue={above!r} was rejected"
    )


_SAME_VALUE = "Requested value is the same as the current provisioned limit"


def _write_current(cognito, value) -> None:
    """Provision ``value`` explicitly: a category never written accepts the value it reports
    once, and a provisioned one refuses an unchanged value with InvalidParameterException."""
    try:
        cognito.update_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION, RequestedLimitValue=value)
    except ClientError as exc:
        if (exc.response["Error"]["Code"], exc.response["Error"].get("Message")) != (
            "InvalidParameterException", _SAME_VALUE
        ):
            raise


def _error(fn):
    """(code, message) of the expected refusal; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message") or ""
    raise AssertionError(f"expected UpdateProvisionedLimit to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
