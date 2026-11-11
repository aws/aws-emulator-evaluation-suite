"""provisioned-limit-numeric-value-precision-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "provisioned-limit-numeric-value-precision-round-trip"
GROUP = "representation"
SERVICES = ["cognito-idp"]

_LIMIT_DEFINITION = {"LimitClass": "API_CATEGORY", "Attributes": {"Category": "UserCreation"}}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cognito-idp-provisioned-limits")
def run(ctx) -> None:
    """GetProvisionedLimit returns the limit as an exact int; UpdateProvisionedLimit rejects the
    current value as a no-op (InvalidParameterException) and one above it as over quota, unchanged.
    """
    idp = ctx.client("cognito-idp")

    original = idp.get_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION)["Limit"]
    original_value = original["ProvisionedLimitValue"]
    free_value = original["FreeLimitValue"]
    assert isinstance(original_value, int) and isinstance(free_value, int), (
        f"GetProvisionedLimit returned non-int limit values: ProvisionedLimitValue={original_value!r}, "
        f"FreeLimitValue={free_value!r}"
    )

    # The same-value comparison runs before the ceiling check, so this is refused on every account
    # once the value is provisioned explicitly.
    _write_current(idp, original_value)
    try:
        idp.update_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION, RequestedLimitValue=original_value)
    except idp.exceptions.InvalidParameterException as exc:
        message = exc.response["Error"].get("Message")
        assert message == _SAME_VALUE, (
            f"UpdateProvisionedLimit(RequestedLimitValue={original_value!r}) raised InvalidParameterException "
            f"for an unexpected reason: {message!r}"
        )
    else:
        raise AssertionError(
            f"UpdateProvisionedLimit(RequestedLimitValue={original_value!r}) succeeded when re-requesting the "
            "account's own current value -- real AWS rejects this as a redundant no-op"
        )

    # Without a Service Quotas increase the ceiling equals the current value.
    above_ceiling = original_value + 1
    try:
        idp.update_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION, RequestedLimitValue=above_ceiling)
    except idp.exceptions.ServiceQuotaExceededException as exc:
        # The current value is within the ceiling and one above it is refused: the ceiling is the current value.
        message = exc.response["Error"].get("Message")
        expected = f"Requested value {above_ceiling} exceeds Service Quota ceiling of {original_value}"
        assert message == expected, (
            f"UpdateProvisionedLimit(RequestedLimitValue={above_ceiling!r}) raised ServiceQuotaExceededException "
            f"with {message!r}, expected {expected!r}"
        )
    else:
        raise AssertionError(
            f"UpdateProvisionedLimit(RequestedLimitValue={above_ceiling!r}) succeeded -- this sandbox account has "
            "no Service Quota increase on file for this limit, so one above the current value should have been "
            "rejected as exceeding the ceiling"
        )

    reread = idp.get_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION)["Limit"]
    reread_value = reread["ProvisionedLimitValue"]
    assert reread_value == original_value, (
        f"GetProvisionedLimit returned {reread_value!r} after two rejected updates, expected the unchanged "
        f"{original_value!r}"
    )
    assert isinstance(reread_value, int), (
        f"GetProvisionedLimit returned ProvisionedLimitValue as {type(reread_value).__name__} after two "
        "rejected updates, expected int"
    )


_SAME_VALUE = "Requested value is the same as the current provisioned limit"


def _write_current(idp, value) -> None:
    """Provision ``value`` explicitly: a category never written accepts the value it reports
    once, and a provisioned one refuses an unchanged value with InvalidParameterException."""
    try:
        idp.update_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION, RequestedLimitValue=value)
    except idp.exceptions.InvalidParameterException as exc:
        if exc.response["Error"].get("Message") != _SAME_VALUE:
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
